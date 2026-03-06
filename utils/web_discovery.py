import json
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import parse_qs, urlparse


PARAMETER_BUCKET_KEYS = ("query", "form", "json", "multipart", "file", "cookie", "path")

DISCOVERY_KEY_MAPPING = {
    "hosts": "hosts",
    "open_ports": "open_ports",
    "ports": "open_ports",
    "services": "services",
    "technologies": "technologies",
    "subdomains": "subdomains",
    "endpoints": "endpoints",
    "forms": "forms",
    "parameters": "parameters",
    "request_nodes": "request_nodes",
    "interactions": "interactions",
}


def empty_parameter_buckets() -> Dict[str, List[str]]:
    return {key: [] for key in PARAMETER_BUCKET_KEYS}


def normalize_parameter_buckets(raw: Any) -> Dict[str, List[str]]:
    normalized = empty_parameter_buckets()
    if not raw:
        return normalized

    if isinstance(raw, dict):
        source = raw
    else:
        source = {"form": raw if isinstance(raw, list) else [str(raw)]}

    legacy_key_map = {
        "get_params": "query",
        "form_params": "form",
        "json_keys": "json",
        "cookie_names": "cookie",
        "path_params": "path",
        "file_params": "file",
    }

    for key, value in source.items():
        bucket = legacy_key_map.get(key, key)
        if bucket not in normalized:
            continue
        values = value if isinstance(value, list) else [value]
        for item in values:
            if item is None:
                continue
            item_str = str(item).strip()
            if item_str and item_str not in normalized[bucket]:
                normalized[bucket].append(item_str)
    return normalized


def merge_parameter_buckets(existing: Any, incoming: Any) -> Dict[str, List[str]]:
    merged = normalize_parameter_buckets(existing)
    incoming_norm = normalize_parameter_buckets(incoming)
    for bucket, values in incoming_norm.items():
        for value in values:
            if value not in merged[bucket]:
                merged[bucket].append(value)
    return merged


def merge_discovery_payload(discoveries: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    for src_key, dst_key in DISCOVERY_KEY_MAPPING.items():
        incoming = data.get(src_key)
        if not incoming:
            continue

        if dst_key == "parameters":
            discoveries[dst_key] = merge_parameter_buckets(discoveries.get(dst_key), incoming)
            continue

        if dst_key == "request_nodes":
            existing_nodes = discoveries.setdefault(dst_key, [])
            discoveries[dst_key] = dedupe_request_nodes([*existing_nodes, *as_list(incoming)])
            continue

        existing = discoveries.setdefault(dst_key, [])
        for item in as_list(incoming):
            if not _contains(existing, item):
                existing.append(item)
    return discoveries


def as_list(value: Any) -> List[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def build_request_nodes(
    discoveries: Dict[str, Any],
    actual_target: str,
    default_headers: Optional[Dict[str, str]] = None,
) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []

    for node in as_list((discoveries or {}).get("request_nodes")):
        normalized = normalize_request_node(node, default_headers=default_headers)
        if normalized:
            nodes.append(normalized)

    if actual_target.startswith(("http://", "https://")):
        nodes.append(
            normalize_request_node(
                {
                    "method": "GET",
                    "url": actual_target,
                    "headers": dict(default_headers or {}),
                    "observed_via": "target",
                },
                default_headers=default_headers,
            )
        )

    for endpoint in as_list((discoveries or {}).get("endpoints")):
        if isinstance(endpoint, str) and endpoint.startswith(("http://", "https://")):
            nodes.append(
                normalize_request_node(
                    {
                        "method": "GET",
                        "url": endpoint,
                        "headers": dict(default_headers or {}),
                        "observed_via": "endpoint",
                    },
                    default_headers=default_headers,
                )
            )
        elif isinstance(endpoint, dict):
            url = endpoint.get("url") or endpoint.get("endpoint")
            if url:
                nodes.append(
                    normalize_request_node(
                        {
                            "method": endpoint.get("method", "GET"),
                            "url": url,
                            "headers": dict(default_headers or {}),
                            "observed_via": endpoint.get("observed_via", "endpoint"),
                        },
                        default_headers=default_headers,
                    )
                )

    for form in as_list((discoveries or {}).get("forms")):
        node = form_to_request_node(form, default_headers=default_headers)
        if node:
            nodes.append(node)

    return dedupe_request_nodes(nodes)


def form_to_request_node(
    form: Dict[str, Any],
    default_headers: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    if not isinstance(form, dict):
        return None

    observed_request = form.get("observed_request") if isinstance(form.get("observed_request"), dict) else {}
    method = str(observed_request.get("method") or form.get("method") or "GET").upper()
    url = observed_request.get("url") or form.get("action")
    if not url:
        return None

    headers = dict(default_headers or {})
    headers.update(observed_request.get("headers") or {})

    fields = form.get("inputs") or []
    base_fields: Dict[str, Any] = {}
    files: Dict[str, Any] = {}
    for field in fields:
        if not isinstance(field, dict):
            continue
        name = field.get("name")
        if not name:
            continue
        field_type = str(field.get("type") or "").lower()
        if field_type in {"submit", "button", "reset", "fieldset"}:
            continue
        if field_type == "file":
            file_meta = dict(field.get("file_template") or {})
            file_meta.setdefault("filename", f"{name or 'upload'}.txt")
            file_meta.setdefault("content_type", "text/plain")
            file_meta.setdefault("content", "ReconForge upload probe")
            files[name] = file_meta
            continue
        base_fields[name] = field.get("value", "")

    content_type = (
        observed_request.get("content_type")
        or form.get("enctype")
        or headers.get("Content-Type")
        or headers.get("content-type")
        or "application/x-www-form-urlencoded"
    )

    node: Dict[str, Any] = {
        "method": method,
        "url": url,
        "headers": headers,
        "content_type": content_type,
        "source_page": form.get("url"),
        "ui_action": form.get("ui_action") or {"kind": "form_submit", "label": form.get("submit_label", "")},
        "observed_via": observed_request.get("observed_via") or form.get("observed_via") or "form",
    }

    if observed_request:
        if observed_request.get("params") is not None:
            node["params"] = observed_request.get("params") or {}
        if observed_request.get("data") is not None:
            node["data"] = observed_request.get("data")
        if observed_request.get("json") is not None:
            node["json"] = observed_request.get("json")
        if observed_request.get("cookies") is not None:
            node["cookies"] = observed_request.get("cookies") or {}
        if observed_request.get("files") is not None:
            node["files"] = normalize_files(observed_request.get("files"))
    else:
        if method == "GET":
            node["params"] = base_fields
        elif _is_json_content_type(content_type):
            node["json"] = base_fields
        else:
            node["data"] = base_fields
        if files:
            node["files"] = normalize_files(files)
    return normalize_request_node(node, default_headers=default_headers)


def normalize_request_node(
    node: Optional[Dict[str, Any]],
    default_headers: Optional[Dict[str, str]] = None,
) -> Optional[Dict[str, Any]]:
    if not isinstance(node, dict):
        return None

    method = str(node.get("method") or "GET").upper()
    url = node.get("url")
    if not isinstance(url, str) or not url:
        return None

    headers = dict(default_headers or {})
    headers.update(node.get("headers") or {})
    params = _normalize_mapping(node.get("params"))
    data = _normalize_body(node.get("data"))
    json_body = _normalize_mapping(node.get("json"))
    cookies = _normalize_mapping(node.get("cookies"))
    files = normalize_files(node.get("files"))
    content_type = (
        node.get("content_type")
        or headers.get("Content-Type")
        or headers.get("content-type")
        or ("multipart/form-data" if files else "application/x-www-form-urlencoded")
    )

    normalized = dict(node)
    normalized.update(
        {
            "method": method,
            "url": url,
            "headers": headers,
            "params": params,
            "data": data,
            "json": json_body,
            "cookies": cookies,
            "files": files,
            "content_type": content_type,
        }
    )
    return normalized


def dedupe_request_nodes(nodes: Iterable[Optional[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for node in nodes:
        normalized = normalize_request_node(node)
        if not normalized:
            continue
        signature = request_node_signature(normalized)
        if signature in seen:
            continue
        seen.add(signature)
        deduped.append(normalized)
    return deduped


def request_node_signature(node: Dict[str, Any]) -> str:
    parts = {
        "method": str(node.get("method") or "GET").upper(),
        "url": node.get("url") or "",
        "params": _jsonish(node.get("params")),
        "data": _jsonish(node.get("data")),
        "json": _jsonish(node.get("json")),
        "files": _jsonish(node.get("files")),
        "content_type": node.get("content_type") or "",
    }
    return json.dumps(parts, sort_keys=True, ensure_ascii=False)


def iter_request_node_parameters(
    request_node: Dict[str, Any],
    *,
    include_files: bool = False,
    include_cookies: bool = False,
) -> List[Dict[str, Any]]:
    injection_points: List[Dict[str, Any]] = []

    for name, value in _normalize_mapping(request_node.get("params")).items():
        injection_points.append(_mk_injection_point("QUERY", name, value))

    json_body = request_node.get("json")
    if isinstance(json_body, dict):
        for name, value in json_body.items():
            injection_points.append(_mk_injection_point("BODY_JSON", name, value))

    data = request_node.get("data")
    if isinstance(data, dict):
        location = "BODY_MULTIPART" if request_node.get("files") else "BODY_FORM"
        for name, value in data.items():
            injection_points.append(_mk_injection_point(location, name, value))

    if include_files:
        for name, value in normalize_files(request_node.get("files")).items():
            injection_points.append(_mk_injection_point("FILE", name, value))

    if include_cookies:
        for name, value in _normalize_mapping(request_node.get("cookies")).items():
            injection_points.append(_mk_injection_point("COOKIE", name, value))

    return injection_points


def extract_path_segments(url: str) -> List[str]:
    parsed = urlparse(url or "")
    return [segment for segment in parsed.path.split("/") if segment]


def collect_candidate_urls(actual_target: str, discoveries: Dict[str, Any]) -> List[str]:
    urls: List[str] = []
    if actual_target.startswith(("http://", "https://")):
        urls.append(actual_target)

    for endpoint in as_list((discoveries or {}).get("endpoints")):
        if isinstance(endpoint, str) and endpoint.startswith(("http://", "https://")):
            urls.append(endpoint)
        elif isinstance(endpoint, dict):
            url = endpoint.get("url") or endpoint.get("endpoint")
            if isinstance(url, str) and url.startswith(("http://", "https://")):
                urls.append(url)

    for node in as_list((discoveries or {}).get("request_nodes")):
        url = (node or {}).get("url")
        if isinstance(url, str) and url.startswith(("http://", "https://")):
            urls.append(url)

    deduped: List[str] = []
    for url in urls:
        if url not in deduped:
            deduped.append(url)
    return deduped


def query_params_from_url(url: str) -> Dict[str, List[str]]:
    parsed = urlparse(url or "")
    return parse_qs(parsed.query, keep_blank_values=True)


def normalize_files(raw_files: Any) -> Dict[str, Dict[str, Any]]:
    files: Dict[str, Dict[str, Any]] = {}
    if not raw_files:
        return files

    if isinstance(raw_files, dict):
        iterable = raw_files.items()
    elif isinstance(raw_files, list):
        iterable = []
        for item in raw_files:
            if isinstance(item, dict):
                field_name = item.get("field_name") or item.get("name")
                if field_name:
                    iterable.append((field_name, item))
    else:
        iterable = []

    for field_name, meta in iterable:
        if not field_name:
            continue
        if not isinstance(meta, dict):
            meta = {"content": str(meta)}
        normalized = dict(meta)
        normalized.setdefault("filename", f"{field_name}.txt")
        normalized.setdefault("content_type", "text/plain")
        normalized.setdefault("content", "ReconForge upload probe")
        files[str(field_name)] = normalized
    return files


def _normalize_mapping(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return dict(value)
    return {}


def _normalize_body(value: Any) -> Any:
    if isinstance(value, dict):
        return dict(value)
    return value


def _contains(items: List[Any], candidate: Any) -> bool:
    candidate_key = _item_key(candidate)
    return any(_item_key(item) == candidate_key for item in items)


def _item_key(item: Any) -> str:
    if isinstance(item, dict):
        return json.dumps(item, sort_keys=True, ensure_ascii=False, default=str)
    return str(item)


def _jsonish(value: Any) -> Any:
    if isinstance(value, dict):
        return {key: _jsonish(val) for key, val in sorted(value.items())}
    if isinstance(value, list):
        return [_jsonish(item) for item in value]
    return value


def _mk_injection_point(location: str, parameter_name: str, original_value: Any) -> Dict[str, Any]:
    return {
        "location": location,
        "parameter_name": parameter_name,
        "original_value": original_value,
    }


def _is_json_content_type(content_type: str) -> bool:
    return "json" in str(content_type or "").lower()
