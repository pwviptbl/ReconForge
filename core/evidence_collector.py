"""
EvidenceCollector — Fase 3

Classifica o nível de prova obtido após as tentativas de exploração e
persiste artefatos (logs de request/response) em dados/evidencias/<run_id>/.

Níveis de prova:
    impact_proven  → ao menos 1 ExploitAttempt com status impact_proven
    partial        → ao menos 1 ExploitAttempt com status partial (sem impact_proven)
    none           → todos os attempts falharam
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import List, Optional

from core.models import Evidence, ExploitAttempt, QueueItem
from utils.logger import get_logger


class EvidenceCollector:
    """
    Classifica e armazena evidências de exploração.

    Uso típico (dentro de StageEvidence):
        collector = EvidenceCollector(base_dir=Path("data/evidencias"))
        evidence = collector.collect(item, attempts)
    """

    def __init__(
        self,
        base_dir: Optional[Path] = None,
        storage=None,
    ):
        self.logger = get_logger("EvidenceCollector")
        self.storage = storage
        self.base_dir = base_dir or Path("data") / "evidencias"
        self.base_dir.mkdir(parents=True, exist_ok=True)

    # -----------------------------------------------------------------------
    # Ponto de entrada principal
    # -----------------------------------------------------------------------

    def collect(
        self,
        item: QueueItem,
        attempts: List[ExploitAttempt],
    ) -> Evidence:
        """
        Analisa as tentativas, classifica o nível de prova e persiste artefatos.

        Args:
            item: QueueItem correspondente às tentativas.
            attempts: Lista de ExploitAttempt executadas.

        Returns:
            Evidence com proof_level classificado e artefatos salvos.
        """
        proof_level, best_attempt = self._classify(attempts)
        artifacts = self._save_artifacts(item, attempts, proof_level)
        impact_summary = self._summarize(item, attempts, proof_level, best_attempt)

        evidence = Evidence(
            queue_item_id=item.id,
            attempt_id=best_attempt.id if best_attempt else "",
            proof_level=proof_level,
            artifacts=artifacts,
            impact_summary=impact_summary,
        )

        if self.storage:
            try:
                self.storage.save_evidence(evidence)
            except Exception as exc:
                self.logger.warning(f"Falha ao persistir evidência {evidence.id}: {exc}")

        self.logger.info(
            f"Evidência coletada: item={item.id} | "
            f"proof_level={proof_level} | "
            f"artifacts={len(artifacts)}"
        )

        return evidence

    def collect_batch(
        self,
        items_and_attempts: List[tuple],  # List[(QueueItem, List[ExploitAttempt])]
    ) -> List[Evidence]:
        """Coleta evidências para múltiplos items."""
        evidences = []
        for item, attempts in items_and_attempts:
            ev = self.collect(item, attempts)
            evidences.append(ev)
        return evidences

    # -----------------------------------------------------------------------
    # Classificação de prova
    # -----------------------------------------------------------------------

    def _classify(
        self,
        attempts: List[ExploitAttempt],
    ) -> tuple:  # (proof_level: str, best_attempt: Optional[ExploitAttempt])
        """
        Determina o nível de prova a partir das tentativas.

        Retorna (proof_level, melhor_attempt).
        """
        # Procurar impact_proven primeiro
        for attempt in attempts:
            if attempt.status == "impact_proven":
                return "impact_proven", attempt

        # Procurar partial
        for attempt in attempts:
            if attempt.status == "partial":
                return "partial", attempt

        return "none", None

    # -----------------------------------------------------------------------
    # Persistência de artefatos
    # -----------------------------------------------------------------------

    def _save_artifacts(
        self,
        item: QueueItem,
        attempts: List[ExploitAttempt],
        proof_level: str,
    ) -> List[str]:
        """
        Salva request/response dos attempts relevantes como arquivos de log.

        Returns:
            Lista de caminhos absolutos dos artefatos salvos.
        """
        artifacts: List[str] = []

        # Criar diretório por run
        run_dir = self.base_dir / f"run_{item.run_id or 'unknown'}"
        run_dir.mkdir(parents=True, exist_ok=True)

        for attempt in attempts:
            if attempt.status not in ("impact_proven", "partial"):
                continue

            log_name = f"{item.category}_{item.id[:8]}_att{attempt.attempt_number}.log"
            log_path = run_dir / log_name

            log_content = self._format_artifact_log(item, attempt)

            try:
                log_path.write_text(log_content, encoding="utf-8")
                artifacts.append(str(log_path.resolve()))
                self.logger.debug(f"Artefato salvo: {log_path}")
            except Exception as exc:
                self.logger.warning(f"Falha ao salvar artefato {log_path}: {exc}")

        # Salvar um JSON completo com a trilha do item mesmo sem confirmação.
        json_name = f"{item.category}_{item.id[:8]}_full.json"
        json_path = run_dir / json_name
        try:
            full_data = {
                "item": item.to_dict(),
                "proof_level": proof_level,
                "attempts": [a.to_dict() for a in attempts],
            }
            if not attempts:
                full_data["note"] = "Nenhuma tentativa foi executada para este item."

            json_path.write_text(
                json.dumps(full_data, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            artifacts.append(str(json_path.resolve()))
        except Exception as exc:
            self.logger.warning(f"Falha ao salvar JSON completo: {exc}")

        return artifacts

    @staticmethod
    def _format_artifact_log(item: QueueItem, attempt: ExploitAttempt) -> str:
        lines = [
            "=" * 60,
            f"ReconForge — Evidência de Exploração",
            "=" * 60,
            f"Timestamp   : {attempt.timestamp}",
            f"Category    : {item.category}",
            f"Target      : {item.target}",
            f"Endpoint    : {item.endpoint}",
            f"Method      : {item.method}",
            f"Parameter   : {item.parameter}",
            f"Context     : {item.context}",
            f"Status      : {attempt.status}",
            f"Attempt #   : {attempt.attempt_number}",
            f"Pipeline    : {attempt.executor}",
            "",
            "--- PAYLOAD UTILIZADO ---",
            attempt.payload_used,
            "",
            "--- REQUEST ---",
            attempt.request_snapshot or "(não disponível)",
            "",
            "--- RESPONSE ---",
            attempt.response_snapshot or "(não disponível)",
            "=" * 60,
        ]
        return "\n".join(lines)

    # -----------------------------------------------------------------------
    # Sumarização
    # -----------------------------------------------------------------------

    def _summarize(
        self,
        item: QueueItem,
        attempts: List[ExploitAttempt],
        proof_level: str,
        best_attempt: Optional[ExploitAttempt],
    ) -> str:
        total = len(attempts)
        confirmed = sum(1 for a in attempts if a.status == "impact_proven")
        partial = sum(1 for a in attempts if a.status == "partial")
        failed = sum(1 for a in attempts if a.status == "failed")

        base = (
            f"Categoria: {item.category.upper()} | "
            f"Endpoint: {item.endpoint} | "
            f"Parâmetro: {item.parameter} | "
            f"Tentativas: {total} (confirmadas={confirmed}, parciais={partial}, falhas={failed})"
        )

        if proof_level == "impact_proven" and best_attempt:
            return (
                f"[CONFIRMADO] {base} | "
                f"Payload: {best_attempt.payload_used[:100]!r}"
            )
        elif proof_level == "partial" and best_attempt:
            return (
                f"[PARCIAL] {base} | "
                f"Payload candidato: {best_attempt.payload_used[:100]!r} — "
                f"verificação manual recomendada"
            )
        else:
            return f"[SEM CONFIRMAÇÃO] {base} — nenhuma tentativa bem-sucedida"
