"""
Estágio de reconhecimento (stage_recon).

Executa os plugins de recon definidos na configuração ou via seleção do
usuário, acumulando hosts, portas, serviços, subdomínios e endpoints
descobertos no WorkflowState.

Plugins típicos deste estágio:
- ReconnaissancePlugin
- PortScannerPlugin
- NmapScannerPlugin
- SubdomainEnumeratorPlugin / SubfinderPlugin
- DNSResolverPlugin
- WhatWebScannerPlugin / TechnologyDetectorPlugin
"""

from typing import Any, Dict, List, Optional

from core.stage_base import ReconStageBase
from core.workflow_state import WorkflowState


# Plugins que pertencem ao estágio de reconhecimento
RECON_PLUGIN_NAMES = [
    "ReconnaissancePlugin",
    "PortScannerPlugin",
    "NmapScannerPlugin",
    "FirewallDetectorPlugin",
    "NetworkMapperPlugin",
    "DNSResolverPlugin",
    "SubdomainEnumeratorPlugin",
    "SubfinderPlugin",
    "WhatWebScannerPlugin",
    "TechnologyDetectorPlugin",
    "ProtocolAnalyzerPlugin",
    "PortExposureAuditPlugin",
    "SSHPolicyCheckPlugin",
    "TrafficAnalyzerPlugin",
]


class StageRecon(ReconStageBase):
    """
    Estágio 1: Reconhecimento.

    Descobre a superfície de ataque do alvo: hosts ativos, portas abertas,
    serviços rodando, tecnologias, subdomínios e endpoints expostos.

    Gate padrão: sempre passa — mesmo sem descobertas, o pipeline continua
    para a detecção (que pode trabalhar apenas com o host principal).
    """

    name = "stage_recon"
    timeout_seconds = 600   # Recon pode demorar — nmap, subfinder, etc.

    def __init__(
        self,
        plugin_manager=None,
        plugin_names: Optional[List[str]] = None,
    ):
        super().__init__()
        self.plugin_manager = plugin_manager
        # Se não especificado, usa a lista padrão de recon
        self.plugin_names = plugin_names or RECON_PLUGIN_NAMES

    def execute(self, state: WorkflowState) -> WorkflowState:
        if not self.plugin_manager:
            self.logger.warning("plugin_manager não configurado em StageRecon — pulando")
            return state

        available = set(self.plugin_manager.plugins.keys())
        to_run = [n for n in self.plugin_names if n in available]

        if not to_run:
            self.logger.info("Nenhum plugin de recon disponível para execução")
            return state

        self.logger.info(f"Plugins de recon a executar: {to_run}")

        for plugin_name in to_run:
            if state.aborted:
                break
            self._run_plugin(plugin_name, state)

        return state

    def _run_plugin(self, plugin_name: str, state: WorkflowState):
        """Executa um plugin e integra os resultados ao WorkflowState."""
        try:
            result = self.plugin_manager.execute_plugin(
                plugin_name,
                state.target,
                state.to_context_dict(),
            )
            if not result:
                return

            state.executed_plugins.append(plugin_name)
            state.plugin_results[plugin_name] = result.to_dict() if hasattr(result, "to_dict") else result

            # Incorporar descobertas ao state.discoveries
            self._merge_discoveries(result, state)

        except Exception as exc:
            self.logger.error(f"Erro ao executar {plugin_name}: {exc}")
            state.errors.append(f"[{self.name}] {plugin_name}: {exc}")

    def _merge_discoveries(self, result: Any, state: WorkflowState):
        """
        Faz merge dos dados de um PluginResult no dicionário discoveries.
        Cobre os campos mais comuns retornados por plugins de recon.
        """
        data: Dict = {}
        if hasattr(result, "data") and isinstance(result.data, dict):
            data = result.data
        elif isinstance(result, dict):
            data = result

        mapping = {
            "hosts": "hosts",
            "open_ports": "open_ports",
            "ports": "open_ports",
            "services": "services",
            "technologies": "technologies",
            "subdomains": "subdomains",
            "endpoints": "endpoints",
            "forms": "forms",
            "parameters": "parameters",
        }

        for src_key, dst_key in mapping.items():
            items = data.get(src_key)
            if not items:
                continue
            if not isinstance(items, list):
                items = [items]
            existing = state.discoveries.setdefault(dst_key, [])
            for item in items:
                if item not in existing:
                    existing.append(item)

    def gate_passes(self, state: WorkflowState) -> bool:
        """Recon sempre passa — não bloquear o pipeline por falta de descobertas."""
        return True
