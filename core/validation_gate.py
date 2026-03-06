"""
ValidationGate — Fase 2

Filtra Findings brutos gerados pelo stage_detect antes de criar QueueItems.

Critérios de aceitação (configuráveis):
- Confidence score acima do threshold mínimo por categoria.
- Parameter não vazio (ou endpoint com query string detectada).
- Sem duplicatas (mesmo endpoint + parâmetro + categoria → mantém o de maior score).

Findings rejeitados vão para state.rejected_findings com motivo de rejeição
anotado em raw_evidence para auditoria.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from core.models import Finding, ValidationResult
from utils.logger import get_logger


# ---------------------------------------------------------------------------
# Thresholds padrão por categoria
# ---------------------------------------------------------------------------

_DEFAULT_THRESHOLDS: Dict[str, float] = {
    "xss":               0.60,
    "sqli":              0.65,
    "ssrf":              0.60,
    "lfi":               0.60,
    "idor":              0.55,
    "auth":              0.70,
    "ssti":              0.65,
    "open_redirect":     0.55,
    "header_injection":  0.55,
    "rce":               0.70,
    "xxe":               0.65,
    "misconfiguration":  0.50,
    "info_disclosure":   0.45,
    "default":           0.50,
}


@dataclass
class GateConfig:
    """Configuração injetável para o ValidationGate."""
    min_confidence: Dict[str, float] = field(default_factory=lambda: dict(_DEFAULT_THRESHOLDS))
    require_parameter: bool = False       # Se True rejeita findings sem parâmetro identificado
    deduplicate: bool = True              # Remove duplicatas mantendo a de maior score
    penalize_no_evidence: float = 0.10   # Penalidade aplicada quando raw_evidence está vazio


class ValidationGate:
    """
    Filtra e normaliza Findings antes de entrarem na ExploitQueue.

    Uso típico (dentro de StageValidate):
        gate = ValidationGate(config=GateConfig())
        result = gate.validate(state.findings)
        state.findings = result.accepted
        state.rejected_findings = result.rejected
    """

    def __init__(self, config: Optional[GateConfig] = None):
        self.config = config or GateConfig()
        self.logger = get_logger("ValidationGate")

    # -----------------------------------------------------------------------
    # Ponto de entrada principal
    # -----------------------------------------------------------------------

    def validate(self, findings: List[Finding]) -> ValidationResult:
        """
        Valida a lista de findings e retorna ValidationResult com
        accepted (passaram) e rejected (reprovados) separados.
        """
        if not findings:
            self.logger.info("ValidationGate: nenhum finding para avaliar.")
            return ValidationResult(accepted=[], rejected=[])

        # Passo 1: aplicar penalidades antes de checar threshold
        for f in findings:
            self._apply_penalties(f)

        # Passo 2: avaliar threshold por categoria
        accepted: List[Finding] = []
        rejected: List[Finding] = []

        for f in findings:
            reason = self._rejection_reason(f)
            if reason:
                f.stage = "false_positive"
                self._annotate_rejection(f, reason)
                rejected.append(f)
            else:
                f.stage = "validated"
                accepted.append(f)

        # Passo 3: deduplicação dos aceitos
        if self.config.deduplicate:
            accepted, dupes = self._deduplicate(accepted)
            rejected.extend(dupes)

        self.logger.info(
            f"ValidationGate: {len(accepted)} aceitos / "
            f"{len(rejected)} rejeitados de {len(findings)} findings"
        )
        return ValidationResult(accepted=accepted, rejected=rejected)

    # -----------------------------------------------------------------------
    # Avaliação individual
    # -----------------------------------------------------------------------

    def _apply_penalties(self, f: Finding) -> None:
        """Aplica penalidade de score quando critérios de qualidade não são atendidos."""
        # Sem evidência bruta: scanner provavelmente só bateu status code
        if not f.raw_evidence.strip():
            f.confidence_score = max(0.0, f.confidence_score - self.config.penalize_no_evidence)

        # Parâmetro ausente mas endpoint tem query string — inferir "?"
        if not f.parameter and "?" in f.endpoint:
            # Tentar extrair primeiro parâmetro da query string
            qs_match = re.search(r"\?([^=&]+)=", f.endpoint)
            if qs_match:
                f.parameter = qs_match.group(1)

    def _rejection_reason(self, f: Finding) -> Optional[str]:
        """Retorna string descrevendo o motivo de rejeição, ou None se aceitar."""
        threshold = self.config.min_confidence.get(
            f.category, self.config.min_confidence.get("default", 0.50)
        )

        if f.confidence_score < threshold:
            return (
                f"confidence {f.confidence_score:.2f} < threshold {threshold:.2f} "
                f"para categoria '{f.category}'"
            )

        if self.config.require_parameter and not f.parameter:
            return "parâmetro vulnerável não identificado"

        return None

    def _annotate_rejection(self, f: Finding, reason: str) -> None:
        """Anota o motivo de rejeição em raw_evidence para auditoria."""
        annotation = f"[REJEITADO: {reason}]"
        if f.raw_evidence:
            f.raw_evidence = f"{annotation}\n{f.raw_evidence}"
        else:
            f.raw_evidence = annotation

    # -----------------------------------------------------------------------
    # Deduplicação
    # -----------------------------------------------------------------------

    def _deduplicate(
        self, findings: List[Finding]
    ) -> Tuple[List[Finding], List[Finding]]:
        """
        Remove achados duplicados: mesmo (endpoint, parameter, category).
        Mantém o de maior confidence_score. Os duplicados viram rejeitados
        com motivo "duplicata de <id_original>".
        """
        seen: Dict[str, Finding] = {}   # key → melhor finding
        dupes: List[Finding] = []

        for f in findings:
            key = self._dedup_key(f)
            if key not in seen:
                seen[key] = f
            else:
                existing = seen[key]
                if f.confidence_score > existing.confidence_score:
                    # Novo é melhor → deslocar o anterior para dupes
                    self._annotate_rejection(
                        existing, f"duplicata de {f.id} (score maior)"
                    )
                    existing.stage = "false_positive"
                    dupes.append(existing)
                    seen[key] = f
                else:
                    # Existente é melhor → deslocar novo para dupes
                    self._annotate_rejection(
                        f, f"duplicata de {existing.id} (score maior)"
                    )
                    f.stage = "false_positive"
                    dupes.append(f)

        return list(seen.values()), dupes

    @staticmethod
    def _dedup_key(f: Finding) -> str:
        """Chave de deduplicação: categoria + endpoint normalizado + parâmetro."""
        # Normaliza endpoint removendo query string
        endpoint = f.endpoint.split("?")[0].rstrip("/").lower()
        return f"{f.category}|{endpoint}|{f.parameter.lower()}"
