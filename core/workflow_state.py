"""
Estado centralizado do workflow de execução do ReconForge.

WorkflowState é o único objeto que transita entre os estágios do pipeline.
Cada estágio recebe o estado, o modifica e o retorna — sem variáveis globais.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from core.models import (
    Evidence,
    ExploitAttempt,
    Finding,
    QueueItem,
    StageStatus,
    Vulnerability,
    _now_iso,
)
from utils.web_discovery import empty_parameter_buckets


@dataclass
class WorkflowState:
    """
    Estado imutável (por convenção) compartilhado entre todos os estágios.

    Os estágios NÃO devem substituir a instância — devem modificar as listas
    e dicionários internos e retornar o mesmo objeto (ou uma cópia explícita).
    """

    # Identificação do run
    target: str
    run_id: int = -1                          # Preenchido pelo Storage ao criar o run
    original_target: str = ""                 # URL completa antes de normalização
    started_at: str = field(default_factory=_now_iso)

    # Dados coletados no stage_recon e stage_detect (legado + novo modelo)
    discoveries: Dict[str, Any] = field(default_factory=lambda: {
        "hosts": [],
        "open_ports": [],
        "services": [],
        "technologies": [],
        "forms": [],
        "endpoints": [],
        "parameters": empty_parameter_buckets(),
        "request_nodes": [],
        "interactions": [],
        "subdomains": [],
    })

    # Vulnerabilidades no modelo legado (compatibilidade com plugins existentes)
    vulnerabilities: List[Vulnerability] = field(default_factory=list)

    # Pipeline novo — Fase 1
    findings: List[Finding] = field(default_factory=list)          # Saída do stage_detect
    rejected_findings: List[Finding] = field(default_factory=list) # Rejeitados pelo ValidationGate
    queue_items: List[QueueItem] = field(default_factory=list)      # Saída do stage_queue_build
    attempts: List[ExploitAttempt] = field(default_factory=list)    # Saída do stage_exploit
    evidences: List[Evidence] = field(default_factory=list)         # Saída do stage_evidence

    # Resultados brutos por plugin (legado)
    plugin_results: Dict[str, Any] = field(default_factory=dict)

    # Controle de estágios
    stage_statuses: Dict[str, StageStatus] = field(default_factory=dict)
    executed_stages: List[str] = field(default_factory=list)
    current_stage: Optional[str] = None

    # Plugins executados (legado — compatibilidade com MinimalOrchestrator)
    executed_plugins: List[str] = field(default_factory=list)
    plugin_states: Dict[str, Any] = field(default_factory=dict)

    # Erros não fatais coletados durante a execução
    errors: List[str] = field(default_factory=list)

    # Configuração ativa (copiada do Config no início do run)
    config: Dict[str, Any] = field(default_factory=dict)

    # Caminho do relatório gerado
    report_path: Optional[str] = None

    # Flag de abort — se True, stages seguintes são pulados
    aborted: bool = False
    abort_reason: str = ""

    # -----------------------------------------------------------------------
    # Helpers de estágio
    # -----------------------------------------------------------------------

    def start_stage(self, stage_name: str) -> StageStatus:
        """Registra início de um estágio e retorna seu StageStatus."""
        status = StageStatus(stage_name=stage_name)
        status.start()
        self.stage_statuses[stage_name] = status
        self.current_stage = stage_name
        return status

    def finish_stage(self, stage_name: str, metrics: Optional[Dict[str, Any]] = None):
        """Registra conclusão bem-sucedida de um estágio."""
        st = self.stage_statuses.get(stage_name)
        if st:
            st.done(metrics)
        if stage_name not in self.executed_stages:
            self.executed_stages.append(stage_name)
        self.current_stage = None

    def skip_stage(self, stage_name: str, reason: str = ""):
        """Registra que um estágio foi pulado (gate não passou)."""
        st = self.stage_statuses.get(stage_name, StageStatus(stage_name=stage_name))
        st.skip(reason)
        self.stage_statuses[stage_name] = st
        self.current_stage = None

    def fail_stage(self, stage_name: str, error: str):
        """Registra falha de um estágio."""
        st = self.stage_statuses.get(stage_name, StageStatus(stage_name=stage_name))
        st.fail(error)
        self.stage_statuses[stage_name] = st
        self.errors.append(f"[{stage_name}] {error}")
        self.current_stage = None

    def abort(self, reason: str):
        """Sinaliza abort do pipeline — stages subsequentes serão pulados."""
        self.aborted = True
        self.abort_reason = reason
        self.errors.append(f"ABORT: {reason}")

    # -----------------------------------------------------------------------
    # Helpers de dados
    # -----------------------------------------------------------------------

    def add_finding(self, finding: Finding):
        """Adiciona finding garantindo run_id correto."""
        finding.run_id = self.run_id
        self.findings.append(finding)

    def get_findings_by_category(self, category: str) -> List[Finding]:
        return [f for f in self.findings if f.category == category]

    def get_queue_by_category(self, category: str) -> List[QueueItem]:
        return [q for q in self.queue_items if q.category == category]

    def get_confirmed_evidences(self) -> List[Evidence]:
        return [e for e in self.evidences if e.proof_level == "impact_proven"]

    def get_partial_evidences(self) -> List[Evidence]:
        return [e for e in self.evidences if e.proof_level == "partial"]

    # -----------------------------------------------------------------------
    # Serialização
    # -----------------------------------------------------------------------

    def to_context_dict(self) -> Dict[str, Any]:
        """
        Serializa o estado para armazenamento no Storage (compatível com
        o formato de contexto esperado pelo MinimalOrchestrator).
        """
        return {
            "target": self.target,
            "original_target": self.original_target,
            "start_time": self.started_at,
            "executed_plugins": self.executed_plugins,
            "plugin_states": self.plugin_states,
            "discoveries": self.discoveries,
            "vulnerabilities": [
                v.to_dict() if hasattr(v, "to_dict") else v
                for v in self.vulnerabilities
            ],
            "errors": self.errors,
            # Pipeline novo
            "findings": [f.to_dict() for f in self.findings],
            "rejected_findings": [f.to_dict() for f in self.rejected_findings],
            "queue_items": [q.to_dict() for q in self.queue_items],
            "stage_statuses": {k: v.to_dict() for k, v in self.stage_statuses.items()},
            "executed_stages": self.executed_stages,
            "aborted": self.aborted,
            "abort_reason": self.abort_reason,
            "report_path": self.report_path,
        }

    def summary(self) -> Dict[str, Any]:
        """Resumo executivo do estado atual para exibição."""
        findings_detected = len(self.findings) + len(self.rejected_findings)
        findings_validated = len(self.findings)
        confirmed = len(self.get_confirmed_evidences())
        partial = len(self.get_partial_evidences())
        return {
            "target": self.target,
            "run_id": self.run_id,
            "stages_done": self.executed_stages,
            "current_stage": self.current_stage,
            "findings": findings_validated,
            "findings_detected": findings_detected,
            "findings_validated": findings_validated,
            "rejected": len(self.rejected_findings),
            "queue_items": len(self.queue_items),
            "attempts": len(self.attempts),
            "evidence_confirmed": confirmed,
            "evidence_partial": partial,
            "vulnerabilities_legacy": len(self.vulnerabilities),
            "errors": len(self.errors),
            "aborted": self.aborted,
        }
