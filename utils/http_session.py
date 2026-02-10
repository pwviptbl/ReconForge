"""
Helpers to build requests Sessions/proxies based on ReconForge config.

Primary goal: allow routing "noisy" plugins through Tor (SOCKS5) when enabled in
config/default.yaml, with an optional per-plugin override via `use_tor`.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import requests

from core.config import get_config


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
    # requests only supports socks* proxies when PySocks is installed.
    if proxy_url.lower().startswith("socks"):
        try:
            import socks  # noqa: F401
        except Exception as e:  # pragma: no cover
            raise RuntimeError(
                "Tor/SOCKS proxy is enabled but PySocks is not installed. "
                "Install `pysocks` (or `requests[socks]`) and try again."
            ) from e


def get_requests_proxies(*, use_tor: bool) -> Optional[Dict[str, str]]:
    """Return a `requests` proxies dict or None."""
    if not use_tor:
        return None

    proxy_url = _tor_proxy_url()
    _ensure_socks_support(proxy_url)
    return {"http": proxy_url, "https": proxy_url}


def create_requests_session(
    *,
    plugin_config: Optional[Dict[str, Any]] = None,
    use_tor: Optional[bool] = None,
    headers: Optional[Dict[str, str]] = None,
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

    if headers:
        session.headers.update(headers)

    return session

