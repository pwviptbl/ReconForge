from __future__ import annotations

from typing import Any, Dict, List
from urllib.parse import urlparse


STATIC_EXTENSIONS = (
    ".js",
    ".css",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".woff",
    ".woff2",
    ".ttf",
    ".map",
    ".webp",
    ".pdf",
)


def build_web_map_payload(discoveries: Dict[str, Any] | None) -> Dict[str, Any]:
    discoveries = discoveries or {}
    parameter_buckets = summarize_parameter_buckets(discoveries.get("parameters", {}))
    forms = summarize_forms(discoveries.get("forms", []))
    requests = summarize_request_nodes(discoveries.get("request_nodes", []))
    interactions = discoveries.get("interactions", [])

    return {
        "parameter_buckets": parameter_buckets,
        "forms": forms,
        "requests": requests,
        "summary": {
            "forms": len(forms),
            "requests_total": len(discoveries.get("request_nodes", [])),
            "requests_interesting": len(requests),
            "interactions": len(interactions) if isinstance(interactions, list) else 0,
        },
    }


def summarize_parameter_buckets(parameters: Any) -> Dict[str, List[str]]:
    if not isinstance(parameters, dict):
        return {}

    normalized: Dict[str, List[str]] = {}
    for bucket, values in parameters.items():
        if not isinstance(values, list):
            continue
        names = sorted({str(value) for value in values if value})
        normalized[str(bucket)] = names
    return normalized


def summarize_forms(forms: Any) -> List[Dict[str, Any]]:
    if not isinstance(forms, list):
        return []

    summaries: List[Dict[str, Any]] = []
    seen = set()
    for form in forms:
        if not isinstance(form, dict):
            continue
        page = str(form.get("url") or "")
        action = str(form.get("action") or page)
        method = str(form.get("method") or "GET").upper()
        enctype = str(form.get("enctype") or "")
        fields: List[str] = []
        for field in form.get("inputs", []):
            if not isinstance(field, dict):
                continue
            name = str(field.get("name") or "").strip()
            if name and name not in fields:
                fields.append(name)
        key = (method, page, action, enctype, tuple(fields))
        if key in seen:
            continue
        seen.add(key)
        summaries.append(
            {
                "page": page,
                "action": action,
                "method": method,
                "enctype": enctype,
                "fields": fields,
            }
        )
    return summaries


def summarize_request_nodes(request_nodes: Any) -> List[Dict[str, Any]]:
    if not isinstance(request_nodes, list):
        return []

    summaries: List[Dict[str, Any]] = []
    seen = set()
    for node in request_nodes:
        if not isinstance(node, dict):
            continue

        url = str(node.get("url") or "")
        if not url or is_static_asset(url):
            continue

        parameter_names: List[str] = []
        for key in ("params", "data", "json", "files", "cookies"):
            value = node.get(key)
            if isinstance(value, dict):
                for name in value.keys():
                    text = str(name).strip()
                    if text and text not in parameter_names:
                        parameter_names.append(text)

        ui_action = node.get("ui_action") if isinstance(node.get("ui_action"), dict) else {}
        action = str(ui_action.get("kind") or "")

        if not parameter_names and action not in {"submit", "click"}:
            continue

        method = str(node.get("method") or "GET").upper()
        key = (method, url, tuple(parameter_names), action)
        if key in seen:
            continue
        seen.add(key)

        summaries.append(
            {
                "method": method,
                "url": url,
                "parameter_names": parameter_names,
                "source_page": str(node.get("source_page") or ""),
                "observed_via": str(node.get("observed_via") or ""),
                "action": action,
            }
        )

    return summaries


def format_web_map_text(run_id: int, target: str, web_map: Dict[str, Any]) -> str:
    lines = [
        f"Run ID: {run_id}",
        f"Target: {target}",
        "",
    ]

    summary = web_map.get("summary", {})
    lines.extend(
        [
            "Resumo",
            f"  Forms: {summary.get('forms', 0)}",
            f"  Requests observadas: {summary.get('requests_total', 0)}",
            f"  Requests úteis: {summary.get('requests_interesting', 0)}",
            f"  Interactions: {summary.get('interactions', 0)}",
            "",
        ]
    )

    parameter_buckets = web_map.get("parameter_buckets", {})
    if parameter_buckets:
        lines.append("Parametros")
        for bucket, values in parameter_buckets.items():
            if values:
                lines.append(f"  {bucket}: {', '.join(values)}")
        lines.append("")

    forms = web_map.get("forms", [])
    if forms:
        lines.append("Formularios")
        for form in forms:
            fields = ", ".join(form.get("fields", [])) or "-"
            lines.append(f"  [{form.get('method', 'GET')}] {form.get('action', '')}")
            lines.append(f"    page: {form.get('page', '')}")
            lines.append(f"    fields: {fields}")
        lines.append("")

    requests = web_map.get("requests", [])
    if requests:
        lines.append("Requests observadas")
        for request in requests:
            params = ", ".join(request.get("parameter_names", [])) or "-"
            action = request.get("action") or "-"
            lines.append(f"  [{request.get('method', 'GET')}] {request.get('url', '')}")
            lines.append(f"    params: {params}")
            lines.append(f"    action: {action}")

    return "\n".join(lines).rstrip()


def is_static_asset(url: str) -> bool:
    path = urlparse(url).path.lower()
    return path.endswith(STATIC_EXTENSIONS)
