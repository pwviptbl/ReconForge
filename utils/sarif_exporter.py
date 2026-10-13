"""
Exportador SARIF 2.1.0 para os findings do ReconForge.

SARIF (Static Analysis Results Interchange Format) é o formato padrão
consumido por GitHub Code Scanning, DefectDojo e outras ferramentas de CI.
Este módulo converte os Finding do WorkflowState em um documento SARIF,
permitindo integrar os resultados do ReconForge a pipelines de CI/CD.

Spec: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# Mapeia confidence_score / severidade legada para o level SARIF.
# SARIF aceita: "error", "warning", "note", "none".
_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _confidence_to_level(confidence: float) -> str:
    if confidence >= 0.8:
        return "error"
    if confidence >= 0.5:
        return "warning"
    return "note"


def _finding_level(finding: Any) -> str:
    sev = getattr(finding, "severity", None)
    if isinstance(sev, str) and sev.lower() in _SEVERITY_TO_LEVEL:
        return _SEVERITY_TO_LEVEL[sev.lower()]
    return _confidence_to_level(getattr(finding, "confidence_score", 0.5) or 0.5)


def _rule_id(category: str) -> str:
    return f"reconforge/{(category or 'unknown').lower()}"


def build_sarif_document(
    findings: List[Any],
    *,
    target: str = "",
    tool_version: str = "1.0.0",
) -> Dict[str, Any]:
    """
    Converte uma lista de Finding em um documento SARIF 2.1.0.

    Cada categoria distinta vira uma `rule`; cada finding vira um `result`
    que referencia a regra correspondente. O endpoint do finding é usado
    como `artifactLocation` (URI), já que o alvo é uma aplicação web.
    """
    rules_by_id: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for finding in findings:
        category = getattr(finding, "category", "unknown") or "unknown"
        rule_id = _rule_id(category)

        if rule_id not in rules_by_id:
            rules_by_id[rule_id] = {
                "id": rule_id,
                "name": category.replace("_", " ").title().replace(" ", ""),
                "shortDescription": {"text": f"Possível vulnerabilidade: {category}"},
                "defaultConfiguration": {"level": _finding_level(finding)},
            }

        endpoint = getattr(finding, "endpoint", "") or getattr(finding, "target", "") or target or "unknown"
        parameter = getattr(finding, "parameter", "") or ""
        method = getattr(finding, "method", "") or ""
        source = getattr(finding, "detection_source", "") or ""
        evidence = getattr(finding, "raw_evidence", "") or ""
        confidence = getattr(finding, "confidence_score", 0.5)

        message_parts = [f"[{category}] detectado por {source}" if source else f"[{category}] detectado"]
        if parameter:
            message_parts.append(f"parâmetro '{parameter}'")
        if method:
            message_parts.append(f"método {method}")
        message = " — ".join(message_parts) + "."
        if evidence:
            message += f" Evidência: {evidence[:300]}"

        result: Dict[str, Any] = {
            "ruleId": rule_id,
            "level": _finding_level(finding),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": endpoint},
                    }
                }
            ],
            "properties": {
                "category": category,
                "parameter": parameter,
                "method": method,
                "detectionSource": source,
                "confidenceScore": confidence,
                "findingId": getattr(finding, "id", ""),
            },
        }
        results.append(result)

    return {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ReconForge",
                        "informationUri": "https://github.com/pwviptbl/ReconForge",
                        "version": tool_version,
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": results,
                "properties": {"target": target},
            }
        ],
    }
