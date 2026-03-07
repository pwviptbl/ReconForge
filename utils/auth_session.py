"""
Helpers para aplicar uma sessao autenticada a requests e Playwright.

O objetivo e manter o recurso simples para o usuario:
- criar um arquivo YAML/JSON com cookies/headers/token
- passar `--session-file`
- reaproveitar o mesmo contexto no mapper, scanners e exploits
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional
from urllib.parse import urlparse

try:
    import yaml
except ImportError:  # pragma: no cover - depende do ambiente
    yaml = None


def load_session_profile(session_file: str | Path | None) -> Dict[str, Any]:
    """Carrega e normaliza um arquivo de sessao YAML/JSON."""
    if not session_file:
        return {}

    path = Path(session_file).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"arquivo de sessao nao encontrado: {path}")

    if path.suffix.lower() in {".yaml", ".yml"} and yaml is not None:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    else:
        raw = json.loads(path.read_text(encoding="utf-8") or "{}")

    if not isinstance(raw, dict):
        raise ValueError("arquivo de sessao deve conter um objeto YAML/JSON")

    return normalize_session_profile(raw, source_path=path)


def normalize_session_profile(raw: Dict[str, Any], source_path: Path | None = None) -> Dict[str, Any]:
    """Normaliza cookies, headers e storage_state em um formato unico."""
    base_url = str(raw.get("base_url") or raw.get("url") or "").strip()
    headers = _normalize_headers(raw.get("headers"))

    bearer_token = raw.get("bearer_token") or raw.get("token")
    if bearer_token and "Authorization" not in headers and "authorization" not in headers:
        headers["Authorization"] = f"Bearer {bearer_token}"

    storage_state_data = None
    storage_state_path = raw.get("storage_state")
    if storage_state_path:
        resolved_storage_state = _resolve_optional_path(storage_state_path, source_path)
        storage_state_path = str(resolved_storage_state)
        try:
            storage_state_data = json.loads(resolved_storage_state.read_text(encoding="utf-8"))
        except Exception as exc:
            raise ValueError(f"storage_state invalido: {resolved_storage_state}: {exc}") from exc

    cookies = _normalize_cookies(
        raw_cookies=raw.get("cookies"),
        cookie_string=raw.get("cookie_string"),
        base_url=base_url,
    )
    if isinstance(storage_state_data, dict):
        cookies.extend(_normalize_cookies(raw_cookies=storage_state_data.get("cookies"), base_url=base_url))

    return {
        "base_url": base_url,
        "headers": headers,
        "cookies": _dedupe_cookies(cookies),
        "cookie_string": cookie_list_to_header(cookies),
        "local_storage": _normalize_local_storage(raw.get("local_storage")),
        "storage_state_path": storage_state_path,
        "storage_state_data": storage_state_data if isinstance(storage_state_data, dict) else None,
    }


def cookie_list_to_header(cookies: Iterable[Dict[str, Any]]) -> str:
    pairs: List[str] = []
    for cookie in cookies or []:
        name = str(cookie.get("name") or "").strip()
        value = str(cookie.get("value") or "")
        if name:
            pairs.append(f"{name}={value}")
    return "; ".join(pairs)


def apply_session_profile_to_requests_session(session: Any, *, session_file: str | Path | None = None, session_profile: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Aplica headers/cookies de sessao em um requests.Session."""
    profile = session_profile or load_session_profile(session_file)
    if not profile:
        return {}

    headers = dict(profile.get("headers") or {})
    if headers:
        session.headers.update(headers)

    for cookie in profile.get("cookies") or []:
        name = str(cookie.get("name") or "").strip()
        if not name:
            continue
        value = str(cookie.get("value") or "")
        cookie_kwargs = {}
        if cookie.get("domain"):
            cookie_kwargs["domain"] = str(cookie["domain"])
        if cookie.get("path"):
            cookie_kwargs["path"] = str(cookie["path"])
        session.cookies.set(name, value, **cookie_kwargs)

    return profile


def request_node_default_headers(session: Any) -> Dict[str, str]:
    """Extrai headers padrao da session incluindo Cookie sintetico para requests observadas virtuais."""
    headers = dict(getattr(session, "headers", {}) or {})
    cookie_dict = getattr(session, "cookies", None)
    if cookie_dict:
        cookie_header = cookie_list_to_header(
            [{"name": name, "value": value} for name, value in cookie_dict.items()]
        )
        if cookie_header:
            headers.setdefault("Cookie", cookie_header)
    return headers


def apply_session_profile_to_prepared_request(
    prepared: Any,
    *,
    session_file: str | Path | None = None,
    session_profile: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Mescla headers/cookies de sessao em um PreparedRequest sem sobrescrever a request observada."""
    profile = session_profile or load_session_profile(session_file)
    if not profile:
        return {}

    for key, value in (profile.get("headers") or {}).items():
        if key not in prepared.headers:
            prepared.headers[key] = value

    cookies_from_request = _parse_cookie_header(prepared.headers.get("Cookie") or prepared.headers.get("cookie") or "")
    for cookie in profile.get("cookies") or []:
        name = str(cookie.get("name") or "").strip()
        if not name or name in cookies_from_request:
            continue
        cookies_from_request[name] = str(cookie.get("value") or "")

    if cookies_from_request:
        prepared.headers["Cookie"] = "; ".join(f"{name}={value}" for name, value in cookies_from_request.items())

    return profile


def playwright_context_options_from_session(
    *,
    session_file: str | Path | None = None,
    session_profile: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Gera kwargs seguros para browser.new_context()."""
    profile = session_profile or load_session_profile(session_file)
    if not profile:
        return {}

    options: Dict[str, Any] = {}
    headers = dict(profile.get("headers") or {})
    if headers:
        options["extra_http_headers"] = headers

    storage_state_path = profile.get("storage_state_path")
    storage_state_data = profile.get("storage_state_data")
    if storage_state_path:
        options["storage_state"] = storage_state_path
    elif storage_state_data:
        options["storage_state"] = storage_state_data

    return options


def apply_local_storage_init_script(page: Any, local_storage: Dict[str, str]) -> None:
    """Registra init script para popular localStorage antes dos scripts da aplicacao."""
    if not local_storage:
        return
    page.add_init_script(
        """
        (items) => {
            const data = items || {};
            for (const [key, value] of Object.entries(data)) {
                try {
                    window.localStorage.setItem(key, String(value));
                } catch (error) {
                }
            }
        }
        """,
        local_storage,
    )


def _normalize_headers(raw_headers: Any) -> Dict[str, str]:
    if not isinstance(raw_headers, dict):
        return {}
    normalized = {}
    for key, value in raw_headers.items():
        key_str = str(key).strip()
        if not key_str:
            continue
        normalized[key_str] = str(value)
    return normalized


def _normalize_local_storage(raw_local_storage: Any) -> Dict[str, str]:
    if not isinstance(raw_local_storage, dict):
        return {}
    normalized = {}
    for key, value in raw_local_storage.items():
        key_str = str(key).strip()
        if not key_str:
            continue
        normalized[key_str] = str(value)
    return normalized


def _normalize_cookies(
    *,
    raw_cookies: Any = None,
    cookie_string: Any = None,
    base_url: str = "",
) -> List[Dict[str, Any]]:
    cookies: List[Dict[str, Any]] = []

    if isinstance(raw_cookies, dict):
        for name, value in raw_cookies.items():
            cookies.append(_cookie_from_pair(str(name), value, base_url))
    elif isinstance(raw_cookies, list):
        for item in raw_cookies:
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                if not name:
                    continue
                cookie = {
                    "name": name,
                    "value": str(item.get("value") or ""),
                }
                for key in ("domain", "path", "url", "expires", "httpOnly", "secure", "sameSite"):
                    if key in item and item[key] is not None:
                        cookie[key] = item[key]
                if not cookie.get("domain") and base_url:
                    cookie["domain"] = _domain_from_url(base_url)
                cookie.setdefault("path", "/")
                cookies.append(cookie)
    if cookie_string:
        for pair in str(cookie_string).split(";"):
            if "=" not in pair:
                continue
            name, value = pair.split("=", 1)
            cookies.append(_cookie_from_pair(name, value, base_url))

    return cookies


def _cookie_from_pair(name: str, value: Any, base_url: str) -> Dict[str, Any]:
    cookie = {
        "name": str(name).strip(),
        "value": str(value).strip(),
        "path": "/",
    }
    if base_url:
        cookie["domain"] = _domain_from_url(base_url)
    return cookie


def _dedupe_cookies(cookies: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    deduped: List[Dict[str, Any]] = []
    seen = set()
    for cookie in cookies or []:
        name = str(cookie.get("name") or "").strip()
        domain = str(cookie.get("domain") or "")
        path = str(cookie.get("path") or "/")
        if not name:
            continue
        key = (name, domain, path)
        if key in seen:
            continue
        seen.add(key)
        deduped.append(cookie)
    return deduped


def _resolve_optional_path(raw_path: Any, source_path: Path | None) -> Path:
    path = Path(str(raw_path)).expanduser()
    if not path.is_absolute() and source_path is not None:
        path = (source_path.parent / path).resolve()
    else:
        path = path.resolve()
    if not path.exists():
        raise FileNotFoundError(f"arquivo nao encontrado: {path}")
    return path


def _domain_from_url(url: str) -> str:
    parsed = urlparse(url)
    return parsed.hostname or parsed.netloc


def _parse_cookie_header(value: str) -> Dict[str, str]:
    cookies: Dict[str, str] = {}
    if not value:
        return cookies
    for part in value.split(";"):
        if "=" not in part:
            continue
        name, cookie_value = part.split("=", 1)
        name = name.strip()
        if name:
            cookies[name] = cookie_value.strip()
    return cookies
