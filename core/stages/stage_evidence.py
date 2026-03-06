"""
StageEvidence — Fase 3

Coleta e classifica evidências a partir dos ExploitAttempt gerados
pelo StageExploit. Cria arquivos de log e um JSON completo por item
em data/evidencias/run_<id>/.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from core.evidence_collector import EvidenceCollector
from core.models import Evidence, ExploitAttempt
from core.stage_base import StageBase
from core.workflow_state import WorkflowState


class StageEvidence(StageBase):
    """
    Estágio 6: Coleta e classificação de evidências.

    Fluxo:
        state.attempts + state.queue_items
            → EvidenceCollector.collect() por item
            → state.evidences (uma Evidence por QueueItem explorado)
    """

    name = "stage_evidence"

    def __init__(self, storage=None, evidence_dir: "Path | None" = None):
        super().__init__()
        self._storage = storage
        self._evidence_dir = evidence_dir or Path("data") / "evidencias"

    def execute(self, state: WorkflowState) -> WorkflowState:
        processed_items = [item for item in state.queue_items if item.status != "pending"]
        if not processed_items:
            self.logger.info("StageEvidence: nenhum item processado para coletar evidências.")
            return state

        collector = EvidenceCollector(
            base_dir=self._evidence_dir,
            storage=self._storage,
        )

        # Agrupar attempts por queue_item_id
        attempts_by_item: Dict[str, List[ExploitAttempt]] = {}
        for attempt in state.attempts:
            attempts_by_item.setdefault(attempt.queue_item_id, []).append(attempt)

        evidences: List[Evidence] = []
        for item in processed_items:
            attempts = attempts_by_item.get(item.id, [])
            evidence = collector.collect(item, attempts)
            evidences.append(evidence)

        state.evidences = evidences

        confirmed = sum(1 for e in evidences if e.proof_level == "impact_proven")
        partial = sum(1 for e in evidences if e.proof_level == "partial")
        none_lvl = sum(1 for e in evidences if e.proof_level == "none")

        self.logger.info(
            f"StageEvidence: {len(evidences)} evidências coletadas | "
            f"confirmadas={confirmed} | parciais={partial} | sem_prova={none_lvl}"
        )
        return state

    def gate_passes(self, state: WorkflowState) -> bool:
        """Sempre avança — evidência vazia ainda é útil para o relatório."""
        return True

    def _collect_metrics(self, state: WorkflowState) -> Dict[str, Any]:
        return {
            "total_evidences": len(state.evidences),
            "impact_proven": sum(1 for e in state.evidences if e.proof_level == "impact_proven"),
            "partial": sum(1 for e in state.evidences if e.proof_level == "partial"),
            "none": sum(1 for e in state.evidences if e.proof_level == "none"),
            "artifacts_total": sum(len(e.artifacts) for e in state.evidences),
        }
