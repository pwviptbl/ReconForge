"""
Helpers for passing proxy settings to subprocess-based tools.

Many CLI tools (Go/Ruby/etc.) will honor one or more of these environment vars:
ALL_PROXY, HTTP_PROXY, HTTPS_PROXY (and lowercase variants).
"""

from __future__ import annotations

import os
from typing import Dict, Optional

from core.config import get_config


def build_proxy_env(*, use_tor: bool, base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    env = dict(base_env) if base_env is not None else dict(os.environ)
    if not use_tor:
        return env

    proxy_url = str(get_config("network.tor.proxy_url", "socks5h://127.0.0.1:9050"))

    # Set both cases to maximize compatibility across tools.
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

