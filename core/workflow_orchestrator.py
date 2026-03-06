"""
Orquestrador de workflow orientado a estágios para o ReconForge.

Executa um pipeline declarativo:

    stage_recon → stage_detect → [stage_validate] → [stage_queue_build]
    → [stage_exploit] → [stage_evidence] → stage_report

Cada estágio:
- Recebe o WorkflowState acumulado.
- Executa sua lógica e atualiza o estado.
- Passa por um gate de decisão antes do próximo estágio avançar.
- Tem seu progresso persistido via checkpoint.
"""

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, Type
from datetime import datetime

# Garantir que a raiz do projeto está no path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from core.config import get_config
from core.models import StageStatus
from core.plugin_manager import PluginManager
from core.stage_base import StageBase
from core.stages.stage_detect import StageDetect
from core.stages.stage_evidence import StageEvidence
from core.stages.stage_exploit import StageExploit
from core.stages.stage_queue_build import StageQueueBuild
from core.stages.stage_recon import StageRecon
from core.stages.stage_report import StageReport
from core.stages.stage_validate import StageValidate
from core.storage import Storage
from core.workflow_state import WorkflowState
from utils.logger import get_logger

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import print as rprint
    _RICH_AVAILABLE = True
except ImportError:
    _RICH_AVAILABLE = False


class WorkflowOrchestrator:
    """
    Orquestrador de pipeline orientado a estágios.

    Uso básico:
        orch = WorkflowOrchestrator()
        state = orch.run("https://alvo.com")
        print(state.summary())

    Uso com plugins específicos por estágio:
        orch = WorkflowOrchestrator(
            recon_plugins=["PortScannerPlugin", "NmapScannerPlugin"],
            detect_plugins=["XssScannerPlugin", "NucleiScannerPlugin"],
        )
        state = orch.run("10.0.0.1")
    """

    def __init__(
        self,
        verbose: bool = False,
        quiet: bool = False,
        recon_plugins: Optional[List[str]] = None,
        detect_plugins: Optional[List[str]] = None,
        data_dir: Optional[str] = None,
        max_exploit_attempts: int = 5,
        exploit_categories: Optional[List[str]] = None,
    ):
        self.logger = get_logger("WorkflowOrchestrator")
        self.verbose = verbose
        self.quiet = quiet
        self.console = Console() if _RICH_AVAILABLE else None

        # Inicializar plugin manager compartilhado
        self.plugin_manager = PluginManager()

        # Storage
        _data_dir = Path(data_dir or get_config("output.data_dir", "dados"))
        self.storage = Storage(_data_dir / "reconforge.db")

        # Configuração dos estágios
        self._recon_plugins = recon_plugins
        self._detect_plugins = detect_plugins
        self._max_exploit_attempts = max_exploit_attempts
        self._exploit_categories = exploit_categories
        self._data_dir = _data_dir

        if not self.quiet:
            self.logger.info(
                f"WorkflowOrchestrator inicializado | "
                f"plugins carregados: {len(self.plugin_manager.plugins)}"
            )

    # -----------------------------------------------------------------------
    # Ponto de entrada principal
    # -----------------------------------------------------------------------

    def run(self, target: str, original_target: Optional[str] = None) -> WorkflowState:
        """
        Executa o pipeline completo de stages para o alvo.

        Args:
            target: Alvo normalizado (host, IP ou domínio).
            original_target: URL original antes de normalização (opcional).

        Returns:
            WorkflowState com o resultado completo do pipeline.
        """
        state = self._init_state(target, original_target or target)
        self._display_start(state)

        stages = self._build_pipeline(state)
        gate_failed_stage: Optional[str] = None

        for stage in stages:
            if state.aborted:
                self.logger.info(f"Pipeline abortado. Motivo: {state.abort_reason}")
                break

            if gate_failed_stage and stage.name != StageReport.name:
                state.skip_stage(
                    stage.name,
                    reason=f"dependente do gate que falhou em {gate_failed_stage}",
                )
                self.storage.checkpoint_workflow(state)
                self._display_stage_result(stage, state)
                continue

            # Executar estágio
            state = stage.run(state)

            # Checkpoint após cada estágio
            self.storage.checkpoint_workflow(state)
            self._display_stage_result(stage, state)

            # Gate de decisão
            if not stage.gate_passes(state):
                self.logger.info(
                    f"Gate do estágio '{stage.name}' não passou — "
                    f"estágios dependentes serão pulados até o relatório final"
                )
                gate_failed_stage = stage.name

        state = self._finalize(state)
        self._display_summary(state)
        return state

    # -----------------------------------------------------------------------
    # Construção do pipeline
    # -----------------------------------------------------------------------

    def _build_pipeline(self, state: WorkflowState) -> List[StageBase]:
        """
        Constrói a lista de estágios a executar.

        Fase 1: StageRecon + StageDetect
        Fase 2: StageValidate + StageQueueBuild
        Fase 3: StageExploit + StageEvidence + StageReport
        """
        evidence_dir = self._data_dir / "evidencias"
        report_dir = self._data_dir / "relatorios"

        stages: List[StageBase] = [
            # ── Fase 1 ─────────────────────────────────────────────────────
            StageRecon(
                plugin_manager=self.plugin_manager,
                plugin_names=self._recon_plugins,
            ),
            StageDetect(
                plugin_manager=self.plugin_manager,
                plugin_names=self._detect_plugins,
            ),
            # ── Fase 2 ─────────────────────────────────────────────────────
            StageValidate(storage=self.storage),
            StageQueueBuild(storage=self.storage),
            # ── Fase 3 ─────────────────────────────────────────────────────
            StageExploit(
                storage=self.storage,
                max_attempts_per_item=self._max_exploit_attempts,
                categories=self._exploit_categories,
            ),
            StageEvidence(
                storage=self.storage,
                evidence_dir=evidence_dir,
            ),
            StageReport(
                output_dir=report_dir,
                storage=self.storage,
            ),
        ]
        return stages

    # -----------------------------------------------------------------------
    # Inicialização do estado
    # -----------------------------------------------------------------------

    def _init_state(self, target: str, original_target: str) -> WorkflowState:
        """Cria e persiste o WorkflowState inicial."""
        state = WorkflowState(
            target=target,
            original_target=original_target,
            config=self._load_config(),
        )

        context_dict = state.to_context_dict()
        run_id = self.storage.create_run(target, context_dict, {})
        state.run_id = run_id

        self.logger.info(f"Run criado: id={run_id} | alvo={target}")
        return state

    def _load_config(self) -> Dict[str, Any]:
        """Carrega configuração ativa para inclusão no WorkflowState."""
        return {
            "network": {
                "threads": get_config("network.threads", 10),
                "timeout": get_config("network.timeout", 30),
                "delay": get_config("network.delay", 0),
            },
            "plugins": {
                "max_parallel": get_config("plugins.max_parallel", 3),
                "default_timeout": get_config("plugins.default_timeout", 300),
            },
            "output": {
                "data_dir": get_config("output.data_dir", "dados"),
            },
        }

    def _finalize(self, state: WorkflowState) -> WorkflowState:
        """Persiste o estado final e calcula métricas de encerramento."""
        self.storage.checkpoint_workflow(state)
        if not self.quiet:
            self.logger.info(
                f"Pipeline finalizado | run_id={state.run_id} | "
                f"stages={state.executed_stages} | "
                f"findings={len(state.findings)}"
            )
        return state

    # -----------------------------------------------------------------------
    # Normalização de alvo
    # -----------------------------------------------------------------------

    @staticmethod
    def normalize_target(target: str) -> str:
        """
        Normaliza o alvo para host/IP quando for URL.
        """
        from urllib.parse import urlparse
        target = target.strip()
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            host = parsed.hostname or parsed.netloc
            return host or target
        if "/" in target:
            target = target.split("/", 1)[0]
        if target.count(":") == 1:
            target = target.split(":", 1)[0]
        return target

    # -----------------------------------------------------------------------
    # Display (Rich quando disponível, fallback para logger)
    # -----------------------------------------------------------------------

    def _display_start(self, state: WorkflowState):
        if self.quiet:
            return
        if _RICH_AVAILABLE and self.console:
            self.console.print(
                Panel(
                    f"[bold cyan]ReconForge Pipeline[/bold cyan]\n"
                    f"Alvo: [yellow]{state.target}[/yellow]  |  "
                    f"Run ID: [green]{state.run_id}[/green]",
                    title="▶ Iniciando workflow",
                    border_style="cyan",
                )
            )
        else:
            self.logger.info(f"▶ Iniciando pipeline | alvo={state.target} run_id={state.run_id}")

    def _display_stage_result(self, stage: StageBase, state: WorkflowState):
        if self.quiet:
            return
        st = state.stage_statuses.get(stage.name)
        if not st:
            return
        status_icon = {"done": "✅", "error": "❌", "skipped": "⏭"}.get(st.status, "•")
        msg = f"{status_icon} {stage.name} | status={st.status} | métricas={st.metrics}"
        if _RICH_AVAILABLE and self.console:
            color = {"done": "green", "error": "red", "skipped": "yellow"}.get(st.status, "white")
            self.console.print(f"[{color}]{msg}[/{color}]")
        else:
            self.logger.info(msg)

    def _display_summary(self, state: WorkflowState):
        if self.quiet:
            return
        summary = state.summary()
        if _RICH_AVAILABLE and self.console:
            table = Table(title=f"Resumo do Run #{state.run_id}", show_header=True)
            table.add_column("Campo", style="cyan")
            table.add_column("Valor", style="white")
            for k, v in summary.items():
                table.add_row(str(k), str(v))
            self.console.print(table)
        else:
            self.logger.info(f"Resumo do run: {summary}")


# ---------------------------------------------------------------------------
# Convenience function para uso via CLI
# ---------------------------------------------------------------------------

def run_pipeline(
    target: str,
    verbose: bool = False,
    quiet: bool = False,
    recon_plugins: Optional[List[str]] = None,
    detect_plugins: Optional[List[str]] = None,
    max_exploit_attempts: int = 5,
    exploit_categories: Optional[List[str]] = None,
) -> WorkflowState:
    """
    Executa o pipeline completo para um alvo.

    Conveniência para uso no scripts/main.py e em testes.
    """
    normalized = WorkflowOrchestrator.normalize_target(target)
    orch = WorkflowOrchestrator(
        verbose=verbose,
        quiet=quiet,
        recon_plugins=recon_plugins,
        detect_plugins=detect_plugins,
        max_exploit_attempts=max_exploit_attempts,
        exploit_categories=exploit_categories,
    )
    return orch.run(normalized, original_target=target)
