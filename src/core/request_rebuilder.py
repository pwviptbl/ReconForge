import json
from typing import Any, Dict, Tuple
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

import requests


def _split_url_query(url: str) -> Tuple[str, Dict[str, Any]]:
    parsed = urlparse(url)
    query_pairs = parse_qs(parsed.query, keep_blank_values=True)
    flat_query: Dict[str, Any] = {}
    for key, values in query_pairs.items():
        if len(values) == 1:
            flat_query[key] = values[0]
        else:
            flat_query[key] = values
    clean_url = urlunparse(parsed._replace(query=""))
    return clean_url, flat_query


def _merge_dict(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in (override or {}).items():
        merged[key] = value
    return merged


def _parse_cookies(headers: Dict[str, str]) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    cookie_header = headers.get("Cookie") or headers.get("cookie")
    if not cookie_header:
        return cookies
    for part in cookie_header.split(";"):
        if "=" not in part:
            continue
        name, value = part.split("=", 1)
        cookies[name.strip()] = value.strip()
    return cookies


def rebuild_attack_request(request_node: Dict[str, Any], injection_point: Dict[str, Any], payload: Any) -> requests.PreparedRequest:
    base = request_node.get("request") or request_node

    method = (base.get("method") or "GET").upper()
    url = base.get("url")
    if not url:
        raise ValueError("request_node missing url")

    headers = dict(base.get("headers") or {})
    params = dict(base.get("params") or {})
    data = base.get("data")
    json_body = base.get("json")
    cookies = dict(base.get("cookies") or {})
    body = base.get("body")

    clean_url, url_params = _split_url_query(url)
    params = _merge_dict(url_params, params)

    location = (injection_point.get("location") or "").upper()
    param_name = injection_point.get("parameter_name")

    if location == "QUERY" and param_name:
        params[param_name] = payload
    elif location == "BODY_FORM" and param_name:
        if isinstance(data, dict):
            form_data = dict(data)
            form_data[param_name] = payload
            data = form_data
        else:
            raw_body = data if data is not None else body
            if isinstance(raw_body, bytes):
                raw_body = raw_body.decode("utf-8", errors="ignore")
            if isinstance(raw_body, str):
                parsed_form = parse_qs(raw_body, keep_blank_values=True)
                parsed_form[param_name] = [payload]
                data = urlencode(parsed_form, doseq=True)
            else:
                data = {param_name: payload}
        json_body = None
    elif location == "BODY_JSON" and param_name:
        if isinstance(json_body, dict):
            json_body = dict(json_body)
            json_body[param_name] = payload
        else:
            raw_body = data if data is not None else body
            if isinstance(raw_body, bytes):
                raw_body = raw_body.decode("utf-8", errors="ignore")
            if isinstance(raw_body, str):
                try:
                    parsed_json = json.loads(raw_body)
                except Exception:
                    parsed_json = {}
            elif isinstance(raw_body, dict):
                parsed_json = dict(raw_body)
            else:
                parsed_json = {}
            parsed_json[param_name] = payload
            json_body = parsed_json
            data = None
    elif location == "HEADER" and param_name:
        headers[param_name] = str(payload)
    elif location == "COOKIE" and param_name:
        if not cookies:
            cookies = _parse_cookies(headers)
        cookies[param_name] = str(payload)
    elif location == "PATH":
        original_value = injection_point.get("original_value")
        if original_value is not None:
            clean_url = clean_url.replace(str(original_value), str(payload), 1)

    req = requests.Request(
        method=method,
        url=clean_url,
        headers=headers or None,
        params=params or None,
        data=data,
        json=json_body,
        cookies=cookies or None,
    )
    return requests.Session().prepare_request(req)
