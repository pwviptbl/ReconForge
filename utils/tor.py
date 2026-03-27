"""
Helpers centralizados para operar o ReconForge em modo Tor.

Objetivos:
- decidir e validar o uso de Tor de forma consistente;
- expor proxies para requests, subprocessos, urllib e Playwright;
- falhar fechado quando Tor estiver habilitado, mas indisponivel.
"""

from __future__ import annotations

import socket
from typing import Any, Dict, Optional, Tuple
from urllib.parse import unquote, urlsplit

from core.config import get_config


def tor_proxy_url() -> str:
    return str(get_config("network.tor.proxy_url", "socks5h://127.0.0.1:9050"))


def is_tor_globally_enabled() -> bool:
    return bool(get_config("network.tor.enabled", False))


def _split_proxy_url(proxy_url: str) -> Tuple[str, str, int, Optional[str], Optional[str]]:
    parsed = urlsplit(proxy_url)
    scheme = (parsed.scheme or "").lower()
    host = parsed.hostname or "127.0.0.1"
    if not scheme:
        raise ValueError(f"proxy_url invalida: {proxy_url}")

    if parsed.port is not None:
        port = parsed.port
    elif scheme.startswith("socks"):
        port = 9050
    elif scheme == "https":
        port = 443
    else:
        port = 80

    username = unquote(parsed.username) if parsed.username else None
    password = unquote(parsed.password) if parsed.password else None
    return scheme, host, port, username, password


def ensure_socks_support(proxy_url: str) -> None:
    if proxy_url.lower().startswith("socks"):
        try:
            import socks  # noqa: F401
        except Exception as exc:  # pragma: no cover
            raise RuntimeError(
                "Tor/SOCKS proxy esta habilitado mas PySocks nao esta instalado. "
                "Instale `pysocks` (ou `requests[socks]`) e tente novamente."
            ) from exc


def ensure_tor_ready(*, use_tor: bool, timeout: float = 1.5) -> None:
    if not use_tor:
        return

    proxy_url = tor_proxy_url()
    ensure_socks_support(proxy_url)
    _, host, port, _, _ = _split_proxy_url(proxy_url)

    try:
        with socket.create_connection((host, port), timeout=timeout):
            return
    except OSError as exc:
        raise RuntimeError(
            f"Tor/proxy configurado em {proxy_url}, mas nao foi possivel conectar em {host}:{port}. "
            "Verifique se o servico Tor esta rodando e escutando na porta configurada."
        ) from exc


def get_requests_proxies(*, use_tor: bool) -> Optional[Dict[str, str]]:
    if not use_tor:
        return None
    proxy_url = tor_proxy_url()
    ensure_tor_ready(use_tor=True)
    return {"http": proxy_url, "https": proxy_url}


def build_proxy_env(*, use_tor: bool, base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    import os

    env = dict(base_env) if base_env is not None else dict(os.environ)
    if not use_tor:
        return env

    proxy_url = tor_proxy_url()
    ensure_tor_ready(use_tor=True)
    env.update(
        {
            "ALL_PROXY": proxy_url,
            "all_proxy": proxy_url,
            "HTTP_PROXY": proxy_url,
            "http_proxy": proxy_url,
            "HTTPS_PROXY": proxy_url,
            "https_proxy": proxy_url,
        }
    )
    return env


def get_playwright_proxy_settings(*, use_tor: bool) -> Optional[Dict[str, str]]:
    if not use_tor:
        return None

    proxy_url = tor_proxy_url()
    ensure_tor_ready(use_tor=True)
    scheme, host, port, username, password = _split_proxy_url(proxy_url)

    # Chromium/Playwright trabalha com "socks5://". Quando usamos SOCKS5,
    # o browser delega a resolucao ao proxy.
    browser_scheme = "socks5" if scheme in {"socks5", "socks5h"} else scheme
    proxy: Dict[str, str] = {"server": f"{browser_scheme}://{host}:{port}"}
    if username:
        proxy["username"] = username
    if password:
        proxy["password"] = password
    return proxy


def collect_tor_status() -> Dict[str, Any]:
    enabled = is_tor_globally_enabled()
    proxy_url = tor_proxy_url()
    status: Dict[str, Any] = {
        "enabled": enabled,
        "proxy_url": proxy_url,
        "proxy_reachable": False,
        "socks_support_available": False,
        "ready": False,
        "issues": [],
    }

    try:
        ensure_socks_support(proxy_url)
        status["socks_support_available"] = True
    except RuntimeError as exc:
        status["issues"].append(str(exc))

    try:
        _, host, port, _, _ = _split_proxy_url(proxy_url)
    except Exception as exc:
        status["issues"].append(str(exc))
        status["ready"] = not enabled and not status["issues"]
        return status

    try:
        with socket.create_connection((host, port), timeout=1.0):
            status["proxy_reachable"] = True
    except OSError as exc:
        status["issues"].append(
            f"Nao foi possivel conectar ao proxy Tor em {host}:{port}: {exc}"
        )

    if enabled:
        status["ready"] = status["proxy_reachable"] and status["socks_support_available"]
    else:
        status["ready"] = True

    return status
