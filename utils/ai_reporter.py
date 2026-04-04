"""
Geração opcional de complemento de relatório via Gemini.

O objetivo aqui não é substituir o relatório técnico do ReconForge.
Ele continua sendo a fonte canônica. Este módulo apenas tenta gerar
um resumo adicional com leitura executiva e técnica quando houver
API configurada e cliente disponível no ambiente.
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List

from core.config import get_config
from utils.web_map import build_web_map_payload

try:  # pragma: no cover - depende do ambiente
    from google import genai
    from google.genai import types as genai_types

    _GEMINI_AVAILABLE = True
except Exception:  # pragma: no cover - depende do ambiente
    genai = None
    genai_types = None
    _GEMINI_AVAILABLE = False


@dataclass
class AIReportResult:
    generated: bool = False
    provider: str = "gemini"
    model: str = ""
    text: str = ""
    skipped_reason: str = ""
    error: str = ""


class AIReportGenerator:
    """Gera uma seção opcional em Markdown para o relatório final."""

    def __init__(self):
        self.provider = str(get_config("report.ai.provider", "gemini"))
        self.model = str(get_config("report.ai.model", "gemini-2.5-flash-lite"))
        self.enabled = bool(get_config("report.ai.enabled", True))
        self.timeout_seconds = int(get_config("report.ai.timeout_seconds", 45))
        self.max_output_tokens = int(get_config("report.ai.max_output_tokens", 1200))
        self.temperature = float(get_config("report.ai.temperature", 0.2))

    def generate_for_state(self, state: Any) -> AIReportResult:
        if not self.enabled:
            return AIReportResult(
                generated=False,
                provider=self.provider,
                model=self.model,
                skipped_reason="disabled",
            )

        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not api_key:
            return AIReportResult(
                generated=False,
                provider=self.provider,
                model=self.model,
                skipped_reason="api_key_missing",
            )

        if self.provider != "gemini":
            return AIReportResult(
                generated=False,
                provider=self.provider,
                model=self.model,
                skipped_reason="unsupported_provider",
            )

        if not _GEMINI_AVAILABLE:
            return AIReportResult(
                generated=False,
                provider=self.provider,
                model=self.model,
                skipped_reason="client_unavailable",
            )

        payload = self._build_payload(state)
        prompt = self._build_prompt(payload)

        try:
            client = genai.Client(api_key=api_key)
            response = client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=genai_types.GenerateContentConfig(
                    temperature=self.temperature,
                    maxOutputTokens=self.max_output_tokens,
                    httpOptions=genai_types.HttpOptions(timeout=self.timeout_seconds * 1000),
                ),
            )
            text = self._extract_text(response)
            if not text.strip():
                return AIReportResult(
                    generated=False,
                    provider=self.provider,
                    model=self.model,
                    skipped_reason="empty_response",
                )
            return AIReportResult(
                generated=True,
                provider=self.provider,
                model=self.model,
                text=text.strip(),
            )
        except Exception as exc:
            return AIReportResult(
                generated=False,
                provider=self.provider,
                model=self.model,
                error=str(exc),
            )

    def _build_payload(self, state: Any) -> Dict[str, Any]:
        confirmed = [e for e in state.evidences if e.proof_level == "impact_proven"]
        partial = [e for e in state.evidences if e.proof_level == "partial"]
        items_by_id = {item.id: item for item in state.queue_items}
        findings_by_id = {finding.id: finding for finding in state.findings + state.rejected_findings}
        web_map = build_web_map_payload(state.discoveries)

        def _serialize_evidence(evidence: Any) -> Dict[str, Any]:
            item = items_by_id.get(evidence.queue_item_id)
            finding = findings_by_id.get(item.finding_id) if item else None
            return {
                "category": item.category if item else "",
                "endpoint": item.endpoint if item else "",
                "method": item.method if item else "",
                "parameter": item.parameter if item else "",
                "impact_summary": evidence.impact_summary,
                "proof_level": evidence.proof_level,
                "detection_source": finding.detection_source if finding else "",
                "confidence_score": getattr(finding, "confidence_score", 0),
            }

        finding_categories = Counter(f.category for f in state.findings)
        techs = []
        for tech in state.discoveries.get("technologies", [])[:10]:
            if isinstance(tech, dict):
                name = str(tech.get("name") or "").strip()
                if name:
                    techs.append(name)
            elif tech:
                techs.append(str(tech))

        return {
            "target": state.target,
            "run_id": state.run_id,
            "summary": {
                "findings_total": len(state.findings) + len(state.rejected_findings),
                "findings_validated": len(state.findings),
                "findings_rejected": len(state.rejected_findings),
                "queue_items": len(state.queue_items),
                "attempts": len(state.attempts),
                "confirmed": len(confirmed),
                "partial": len(partial),
                "requests_observed": len(state.discoveries.get("request_nodes", [])),
                "forms_mapped": len(state.discoveries.get("forms", [])),
                "endpoints_mapped": len(state.discoveries.get("endpoints", [])),
            },
            "top_categories": dict(finding_categories.most_common(6)),
            "technologies": techs,
            "confirmed_evidences": [_serialize_evidence(evidence) for evidence in confirmed[:8]],
            "partial_evidences": [_serialize_evidence(evidence) for evidence in partial[:8]],
            "web_mapping": {
                "forms": web_map.get("forms", [])[:8],
                "requests": web_map.get("requests", [])[:10],
                "parameter_buckets": web_map.get("parameter_buckets", {}),
            },
        }

    def _build_prompt(self, payload: Dict[str, Any]) -> str:
        return (
            "Você é um consultor sênior de segurança ofensiva escrevendo um complemento de relatório.\n"
            "Escreva em português brasileiro, de forma objetiva e profissional.\n"
            "Use apenas os dados fornecidos. Não invente vulnerabilidades, impactos ou contexto.\n"
            "Se não houver exploração confirmada, diga isso explicitamente.\n"
            "A resposta deve ser Markdown e conter exatamente estas seções nesta ordem:\n"
            "## 🤖 Resumo Executivo Assistido por IA\n"
            "## 🛠️ Leitura Técnica Assistida por IA\n"
            "No resumo executivo, explique o risco geral, os principais impactos e as prioridades imediatas.\n"
            "Na leitura técnica, destaque vetores relevantes, endpoints, parâmetros e observações práticas para remediation.\n"
            "Seja conciso: no máximo 8 parágrafos curtos ou bullets no total.\n\n"
            "Dados estruturados do run:\n"
            f"{json.dumps(payload, ensure_ascii=False, indent=2)}"
        )

    def _extract_text(self, response: Any) -> str:
        text = getattr(response, "text", "") or ""
        if text:
            return str(text)

        candidates: List[str] = []
        for candidate in getattr(response, "candidates", []) or []:
            content = getattr(candidate, "content", None)
            parts = getattr(content, "parts", []) if content else []
            for part in parts:
                part_text = getattr(part, "text", "") or ""
                if part_text:
                    candidates.append(str(part_text))

        return "\n".join(candidates).strip()
