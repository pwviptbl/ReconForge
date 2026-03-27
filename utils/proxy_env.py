"""
Helpers for passing proxy settings to subprocess-based tools.
"""

from __future__ import annotations

from typing import Dict, Optional

from utils.tor import build_proxy_env as _build_proxy_env


def build_proxy_env(*, use_tor: bool, base_env: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    return _build_proxy_env(use_tor=use_tor, base_env=base_env)
