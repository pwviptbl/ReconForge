"""
Geração opcional de complemento de relatório via IA (Together AI ou Gemini).

O objetivo aqui não é substituir o relatório técnico do ReconForge.
Ele continua sendo a fonte canônica. Este módulo gera um resumo
adicional com leitura executiva, análise técnica e remediação orientada
a Governança, Risco e Conformidade (GRC).
"""

from __future__ import annotations

import json
import os
from collections import Counter
from dataclasses import dataclass
from typing import Any, Dict, List

import requests

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
    provider: str = "together"
    model: str = ""
    text: str = ""
    skipped_reason: str = ""
    error: str = ""


class AIReportGenerator:
    """Gera uma seção executiva e técnica em Markdown para o relatório final."""

    def __init__(self):
        # Auto-detecção de provider caso não especificado:
        default_provider = "together" if os.getenv("TOGETHER_API_KEY") else "gemini"
        self.provider = str(get_config("report.ai.provider", default_provider)).lower().strip()

        if self.provider == "together":
            default_model = os.getenv("TOGETHER_MODEL", "deepseek-ai/DeepSeek-V4.1-Flash")
        else:
            default_model = "gemini-2.5-flash-lite"

        self.model = str(get_config("report.ai.model", default_model))
        self.enabled = bool(get_config("report.ai.enabled", True))
        self.timeout_seconds = int(get_config("report.ai.timeout_seconds", 60))
        self.max_output_tokens = int(get_config("report.ai.max_output_tokens", 2000))
        self.temperature = float(get_config("report.ai.temperature", 0.2))

    def generate_for_state(self, state: Any) -> AIReportResult:
        if not self.enabled:
            return AIReportResult(
                generated=False,
                provider=self.provider,
                model=self.model,
                skipped_reason="disabled",
            )

        if self.provider == "together":
            return self._generate_with_together(state)
        elif self.provider == "gemini":
            return self._generate_with_gemini(state)
        else:
            return AIReportResult(
                generated=False,
                provider=self.provider,
                model=self.model,
                skipped_reason="unsupported_provider",
            )

    def _generate_with_together(self, state: Any) -> AIReportResult:
        api_key = (
            os.getenv("TOGETHER_API_KEY", "").strip()
            or os.getenv("TOGETHERAI_API_KEY", "").strip()
        )
        if not api_key:
            return AIReportResult(
                generated=False,
                provider="together",
                model=self.model,
                skipped_reason="api_key_missing",
            )

        payload = self._build_payload(state)
        prompt = self._build_prompt(payload)

        url = "https://api.together.xyz/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json",
            "User-Agent": "ReconForge/2.0-GRC",
        }
        body = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Você é um consultor sênior de segurança ofensiva e governança cibernética (GRC/AppSec). "
                        "Escreva em português brasileiro de forma técnica, objetiva e baseada exclusivamente em fatos. "
                        "Não invente vulnerabilidades nem exagere impactos."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            "temperature": self.temperature,
            "max_tokens": self.max_output_tokens,
        }

        try:
            resp = requests.post(url, headers=headers, json=body, timeout=self.timeout_seconds)
            if resp.status_code != 200:
                return AIReportResult(
                    generated=False,
                    provider="together",
                    model=self.model,
                    error=f"HTTP {resp.status_code}: {resp.text[:300]}",
                )

            data = resp.json()
            choices = data.get("choices", [])
            if not choices:
                return AIReportResult(
                    generated=False,
                    provider="together",
                    model=self.model,
                    skipped_reason="empty_response",
                )

            text = choices[0].get("message", {}).get("content", "").strip()
            if not text:
                return AIReportResult(
                    generated=False,
                    provider="together",
                    model=self.model,
                    skipped_reason="empty_response",
                )

            return AIReportResult(
                generated=True,
                provider="together",
                model=self.model,
                text=text,
            )
        except Exception as exc:
            return AIReportResult(
                generated=False,
                provider="together",
                model=self.model,
                error=str(exc),
            )

    def _generate_with_gemini(self, state: Any) -> AIReportResult:
        api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not api_key:
            return AIReportResult(
                generated=False,
                provider="gemini",
                model=self.model,
                skipped_reason="api_key_missing",
            )

        if not _GEMINI_AVAILABLE:
            return AIReportResult(
                generated=False,
                provider="gemini",
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
                    provider="gemini",
                    model=self.model,
                    skipped_reason="empty_response",
                )
            return AIReportResult(
                generated=True,
                provider="gemini",
                model=self.model,
                text=text.strip(),
            )
        except Exception as exc:
            return AIReportResult(
                generated=False,
                provider="gemini",
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
                "candidate_payload": item.candidate_payload if item else "",
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
                "open_ports": state.discoveries.get("open_ports", []),
            },
            "top_categories": dict(finding_categories.most_common(6)),
            "technologies": techs,
            "confirmed_evidences": [_serialize_evidence(evidence) for evidence in confirmed[:12]],
            "partial_evidences": [_serialize_evidence(evidence) for evidence in partial[:12]],
            "web_mapping": {
                "forms": web_map.get("forms", [])[:8],
                "requests": web_map.get("requests", [])[:10],
                "parameter_buckets": web_map.get("parameter_buckets", {}),
            },
        }

    def _build_prompt(self, payload: Dict[str, Any]) -> str:
        return (
            "Você é um consultor sênior de segurança ofensiva escrevendo um complemento de relatório para o GRC.\n"
            "Escreva em português brasileiro, de forma objetiva, profissional e técnica.\n"
            "Use apenas os dados fornecidos. Não invente vulnerabilidades, impactos ou contexto fictício.\n"
            "Se não houver exploração confirmada, afirme isso explicitamente.\n\n"
            "A resposta DEVE ser em Markdown e conter exatamente estas seções:\n"
            "## 🤖 Resumo Executivo e Postura de Risco\n"
            "## 🛠️ Análise Técnica de Vetores e Impacto\n"
            "## 🛡️ Recomendações e Plano de Ação (Remediação)\n\n"
            "- No Resumo Executivo: explique a postura geral de risco do alvo para o CISO e diretoria.\n"
            "- Na Análise Técnica: detalhe endpoints, parâmetros críticos e vetores confirmados.\n"
            "- No Plano de Ação: forneça orientações práticas e códigos/configurações recomendadas para os desenvolvedores mitigarem as falhas.\n\n"
            "Dados estruturados do scan ReconForge:\n"
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
