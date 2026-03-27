"""
Helpers to build requests Sessions/proxies based on ReconForge config.

Primary goal: allow routing "noisy" plugins through Tor (SOCKS5) when enabled in
config/default.yaml, with an optional per-plugin override via `use_tor`.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import requests

from core.config import get_config
from utils.auth_session import apply_session_profile_to_requests_session, request_node_default_headers
from utils.tor import ensure_tor_ready, get_requests_proxies as _tor_requests_proxies


def resolve_use_tor(plugin_config: Optional[Dict[str, Any]] = None, use_tor: Optional[bool] = None) -> bool:
    """
    Decide whether to use Tor for a given plugin execution.

    Precedence:
    1) explicit `use_tor` argument (if not None)
    2) plugin_config['use_tor'] (if present and not None)
    3) global config `network.tor.enabled`
    """
    if use_tor is not None:
        return bool(use_tor)

    if plugin_config is not None:
        plugin_value = plugin_config.get("use_tor")
        if plugin_value is not None:
            return bool(plugin_value)

    return bool(get_config("network.tor.enabled", False))


def _tor_proxy_url() -> str:
    return str(get_config("network.tor.proxy_url", "socks5h://127.0.0.1:9050"))


def _ensure_socks_support(proxy_url: str) -> None:
    # Mantido por compatibilidade local para chamadas antigas.
    ensure_tor_ready(use_tor=True)


def get_requests_proxies(*, use_tor: bool) -> Optional[Dict[str, str]]:
    """Return a `requests` proxies dict or None."""
    return _tor_requests_proxies(use_tor=use_tor)


def create_requests_session(
    *,
    plugin_config: Optional[Dict[str, Any]] = None,
    use_tor: Optional[bool] = None,
    headers: Optional[Dict[str, str]] = None,
    session_file: Optional[str] = None,
) -> requests.Session:
    """
    Build a requests.Session with optional Tor proxies applied.

    Note: timeouts still need to be passed per-request.
    """
    session = requests.Session()

    enabled = resolve_use_tor(plugin_config=plugin_config, use_tor=use_tor)
    proxies = get_requests_proxies(use_tor=enabled)
    if proxies:
        session.proxies.update(proxies)
        # Avoid mixing environment proxy settings with our explicit proxy.
        session.trust_env = False

    if session_file:
        apply_session_profile_to_requests_session(session, session_file=session_file)

    if headers:
        session.headers.update(headers)

    return session


def build_request_node_headers(session: requests.Session) -> Dict[str, str]:
    """Exporta headers padrao da session, incluindo Cookie quando houver."""
    return request_node_default_headers(session)
