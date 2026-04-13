"""
StageQueueBuild — Fase 2

Constrói a ExploitQueue a partir dos findings validados pelo StageValidate.
Cada finding aceito origina um QueueItem com prioridade calculada por categoria.
"""

from __future__ import annotations

from typing import Any, Dict, List

from core.exploit_queue import ExploitQueue
from core.models import Finding
from core.stage_base import StageBase
from core.workflow_state import WorkflowState
from utils.web_discovery import build_request_nodes, find_request_template_matches


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
        request_nodes = build_request_nodes(
            state.discoveries,
            state.original_target or state.target,
        )
        findings_for_queue = self._expand_findings(state.findings, request_nodes)
        items = queue.enqueue(findings_for_queue)

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

    def _expand_findings(
        self,
        findings: List[Finding],
        request_nodes: List[Dict[str, Any]],
    ) -> List[Finding]:
        expanded: List[Finding] = []

        for finding in findings:
            # Se for um finding passivo, explodir em categorias de teste reais
            if finding.category == "passive":
                target_categories = ["xss", "sqli", "ssrf", "lfi", "idor"]
                for cat in target_categories:
                    clone = Finding.from_dict(finding.to_dict())
                    clone.category = cat
                    # Re-processar para encontrar RequestNode original se possível
                    matches = find_request_template_matches(
                        clone.endpoint,
                        request_nodes,
                        parameter=clone.parameter,
                    )
                    if matches:
                        match = matches[0] # Pegar o melhor match
                        request_node = match["request_node"]
                        injection_point = match["injection_point"]
                        clone.method = str(request_node.get("method") or clone.method or "GET").upper()
                        clone.endpoint = str(request_node.get("url") or clone.endpoint)
                        clone.parameter = str(injection_point.get("parameter_name") or clone.parameter)
                        original_value = injection_point.get("original_value")
                        if original_value not in (None, ""):
                            clone.candidate_payload = str(original_value)
                    
                    expanded.append(clone)
                continue

            # Comportamento padrão para findings já categorizados
            matches = find_request_template_matches(
                finding.endpoint,
                request_nodes,
                parameter=finding.parameter,
            )
            if not matches:
                expanded.append(finding)
                continue

            deduped_matches = []
            seen = set()
            for match in matches:
                request_node = match["request_node"]
                injection_point = match["injection_point"]
                signature = (
                    request_node.get("method", "GET"),
                    request_node.get("url", finding.endpoint),
                    injection_point.get("parameter_name", ""),
                )
                if signature in seen:
                    continue
                seen.add(signature)
                deduped_matches.append(match)

            if not deduped_matches:
                expanded.append(finding)
                continue

            for match in deduped_matches:
                request_node = match["request_node"]
                injection_point = match["injection_point"]
                clone = Finding.from_dict(finding.to_dict())
                clone.method = str(request_node.get("method") or clone.method or "GET").upper()
                clone.endpoint = str(request_node.get("url") or clone.endpoint)
                clone.parameter = str(injection_point.get("parameter_name") or clone.parameter)
                original_value = injection_point.get("original_value")
                if original_value not in (None, ""):
                    clone.candidate_payload = str(original_value)
                expanded.append(clone)

        return expanded
