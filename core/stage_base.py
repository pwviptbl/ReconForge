"""
Interface base para todos os estágios do workflow do ReconForge.

Cada estágio do pipeline (recon, detect, validate, queue_build, exploit,
evidence, report) implementa StageBase. O WorkflowOrchestrator os executa
em sequência, verificando o gate de cada um antes de prosseguir.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from core.models import StageStatus
from core.workflow_state import WorkflowState
from utils.logger import get_logger


class StageBase(ABC):
    """
    Classe base para estágios do pipeline de execução do ReconForge.

    Contrato de um estágio:
    - Recebe: WorkflowState com o acumulado até o momento.
    - Executa: lógica do estágio, modifica o estado in-place.
    - Retorna: o mesmo WorkflowState atualizado.
    - Gate: decide se o pipeline pode continuar para o próximo estágio.
    """

    #: Nome único do estágio — usado como chave em stage_statuses.
    name: str = "base_stage"

    #: Timeout em segundos. 0 = sem limite.
    timeout_seconds: int = 300

    def __init__(self):
        self.logger = get_logger(self.__class__.__name__)

    def run(self, state: WorkflowState) -> WorkflowState:
        """
        Ponto de entrada chamado pelo WorkflowOrchestrator.

        Gerencia o ciclo de vida do StageStatus (start → done/fail) e
        captura exceções não tratadas sem derrubar o pipeline inteiro.
        """
        if state.aborted:
            state.skip_stage(self.name, reason="pipeline abortado anteriormente")
            return state

        st = state.start_stage(self.name)
        self.logger.info(f"▶ Início do estágio: {self.name} | alvo: {state.target}")

        try:
            state = self.execute(state)
            metrics = self._collect_metrics(state)
            state.finish_stage(self.name, metrics)
            self.logger.info(f"✅ Estágio concluído: {self.name} | métricas: {metrics}")
        except Exception as exc:
            err = f"{type(exc).__name__}: {exc}"
            self.logger.error(f"❌ Erro no estágio {self.name}: {err}")
            state.fail_stage(self.name, err)

        return state

    @abstractmethod
    def execute(self, state: WorkflowState) -> WorkflowState:
        """
        Lógica principal do estágio. Deve ser implementado por cada estágio.

        Args:
            state: Estado atual do workflow.

        Returns:
            WorkflowState atualizado com os resultados deste estágio.
        """
        pass

    def gate_passes(self, state: WorkflowState) -> bool:
        """
        Critério de decisão para prosseguir ao próximo estágio.

        Retorna True por padrão — subclasses sobrescrevem quando necessário.
        Exemplo: stage_validate retorna False se zero findings foram aceitos.
        """
        return True

    def _collect_metrics(self, state: WorkflowState) -> Dict[str, Any]:
        """
        Coleta métricas relevantes do estado após a execução.
        Subclasses podem sobrescrever para métricas específicas.
        """
        return {
            "findings": len(state.findings),
            "queue_items": len(state.queue_items),
            "evidences": len(state.evidences),
        }


class ReconStageBase(StageBase):
    """Base para estágios de reconhecimento (recon, detect)."""

    def _collect_metrics(self, state: WorkflowState) -> Dict[str, Any]:
        base = super()._collect_metrics(state)
        base.update({
            "hosts": len(state.discoveries.get("hosts", [])),
            "open_ports": len(state.discoveries.get("open_ports", [])),
            "endpoints": len(state.discoveries.get("endpoints", [])),
            "subdomains": len(state.discoveries.get("subdomains", [])),
        })
        return base


class ExploitStageBase(StageBase):
    """Base para estágios de exploração e evidência."""

    def _collect_metrics(self, state: WorkflowState) -> Dict[str, Any]:
        base = super()._collect_metrics(state)
        confirmed = len(state.get_confirmed_evidences())
        partial = len(state.get_partial_evidences())
        base.update({
            "attempts": len(state.attempts),
            "evidence_confirmed": confirmed,
            "evidence_partial": partial,
            "evidence_none": len(state.evidences) - confirmed - partial,
        })
        return base
