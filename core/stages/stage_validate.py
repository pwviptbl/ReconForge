"""
StageValidate — Fase 2

Aplica o ValidationGate sobre os findings brutos gerados pelo StageDetect.
Findings que não passam pelo gate vão para state.rejected_findings.
Gate final: aborta o pipeline se 0 findings foram aceitos.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.stage_base import StageBase
from core.validation_gate import GateConfig, ValidationGate
from core.workflow_state import WorkflowState


class StageValidate(StageBase):
    """
    Estágio 3: Validação de qualidade dos findings.

    Fluxo:
        findings (brutos do StageDetect)
            → ValidationGate (thresholds + dedup)
            → state.findings (aceitos)
            → state.rejected_findings (reprovados)
    """

    name = "stage_validate"

    def __init__(self, gate_config: "GateConfig | None" = None, storage=None):
        super().__init__()
        self._gate_config = gate_config
        self._storage = storage

    def execute(self, state: WorkflowState) -> WorkflowState:
        if not state.findings:
            self.logger.info("StageValidate: nenhum finding para validar.")
            return state

        # Construir configuração do gate (pode sobrescrever thresholds via config do run)
        config = self._build_gate_config(state)
        gate = ValidationGate(config=config)

        result = gate.validate(state.findings)

        state.findings = result.accepted
        state.rejected_findings.extend(result.rejected)

        # Persistir findings aceitos com stage = "validated"
        if self._storage:
            for f in result.accepted:
                try:
                    self._storage.update_finding_stage(f.id, "validated")
                except Exception as exc:
                    self.logger.warning(f"Falha ao persistir stage do finding {f.id}: {exc}")

        return state

    def gate_passes(self, state: WorkflowState) -> bool:
        """Pipeline avança somente se houver ao menos 1 finding aceito."""
        if not state.findings:
            self.logger.info("StageValidate gate: 0 findings válidos — encerrando pipeline.")
            return False
        return True

    def _build_gate_config(self, state: WorkflowState) -> GateConfig:
        if self._gate_config:
            return self._gate_config

        # Tentar carregar thresholds da config do run
        validation_cfg = state.config.get("validation", {})
        thresholds = validation_cfg.get("min_confidence", {})
        require_param = validation_cfg.get("require_parameter", False)

        config = GateConfig(require_parameter=require_param)
        if thresholds:
            config.min_confidence.update(thresholds)
        return config

    def _collect_metrics(self, state: WorkflowState) -> Dict[str, Any]:
        return {
            "accepted": len(state.findings),
            "rejected": len(state.rejected_findings),
            "acceptance_rate": (
                round(len(state.findings) / max(1, len(state.findings) + len(state.rejected_findings)), 2)
            ),
        }
