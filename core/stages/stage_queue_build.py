"""
StageQueueBuild — Fase 2

Constrói a ExploitQueue a partir dos findings validados pelo StageValidate.
Cada finding aceito origina um QueueItem com prioridade calculada por categoria.
"""

from __future__ import annotations

from typing import Any, Dict

from core.exploit_queue import ExploitQueue
from core.stage_base import StageBase
from core.workflow_state import WorkflowState


class StageQueueBuild(StageBase):
    """
    Estágio 4: Construção da fila de exploração.

    Fluxo:
        state.findings (validados)
            → ExploitQueue.enqueue()
            → state.queue_items (ordenados por prioridade)
    """

    name = "stage_queue_build"

    def __init__(self, storage=None):
        super().__init__()
        self._storage = storage

    def execute(self, state: WorkflowState) -> WorkflowState:
        if not state.findings:
            self.logger.info("StageQueueBuild: nenhum finding validado para enfileirar.")
            return state

        queue = ExploitQueue(storage=self._storage)
        items = queue.enqueue(state.findings)

        state.queue_items = items
        self.logger.info(
            f"StageQueueBuild: {len(items)} items enfileirados | "
            f"categorias: {sorted({i.category for i in items})}"
        )
        return state

    def gate_passes(self, state: WorkflowState) -> bool:
        """Avança somente se a queue tiver itens pendentes."""
        pending = [i for i in state.queue_items if i.status == "pending"]
        if not pending:
            self.logger.info("StageQueueBuild gate: queue vazia — encerrando pipeline.")
            return False
        return True

    def _collect_metrics(self, state: WorkflowState) -> Dict[str, Any]:
        by_cat: Dict[str, int] = {}
        by_pri: Dict[int, int] = {}
        for item in state.queue_items:
            by_cat[item.category] = by_cat.get(item.category, 0) + 1
            by_pri[item.priority] = by_pri.get(item.priority, 0) + 1

        return {
            "total_queued": len(state.queue_items),
            "by_category": by_cat,
            "by_priority": by_pri,
        }
