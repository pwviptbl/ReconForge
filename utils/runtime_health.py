from __future__ import annotations

import importlib.util
import sys
from typing import Any, Dict, List

from core.plugin_manager import PluginManager
from utils.runtime_profiles import list_profiles, resolve_profile_plugins
from utils.tor import collect_tor_status


def collect_runtime_health(plugin_manager: PluginManager | None = None) -> Dict[str, Any]:
    manager = plugin_manager or PluginManager()
    plugin_health = manager.get_health_report()
    available_plugins = plugin_health.get("loaded_plugins", [])

    profiles: List[Dict[str, Any]] = []
    for profile in list_profiles():
        resolved = resolve_profile_plugins(profile["name"], available_plugins)
        expected_recon_plugins = list(profile.get("recon_plugins", []))
        expected_detect_plugins = list(profile.get("detect_plugins", []))
        expected_plugins = sorted(set(expected_recon_plugins + expected_detect_plugins))
        missing_plugins = [name for name in expected_plugins if name not in available_plugins]
        profiles.append(
            {
                "name": profile["name"],
                "description": profile.get("description", ""),
                "missing_required": resolved["missing_required"],
                "missing_plugins": missing_plugins,
                "expected_recon_plugins": expected_recon_plugins,
                "expected_detect_plugins": expected_detect_plugins,
                "available_recon_plugins": resolved["recon_plugins"],
                "available_detect_plugins": resolved["detect_plugins"],
            }
        )

    return {
        "python_executable": sys.executable,
        "playwright_module_available": importlib.util.find_spec("playwright") is not None,
        "tor": collect_tor_status(),
        "plugin_health": plugin_health,
        "profiles": profiles,
    }


def format_runtime_health_text(health: Dict[str, Any]) -> str:
    lines = [
        f"Python: {health.get('python_executable', 'N/A')}",
        f"Playwright module: {'ok' if health.get('playwright_module_available') else 'missing'}",
        _format_tor_line(health.get("tor", {})),
        "",
        "Plugins",
        f"  Loaded: {health.get('plugin_health', {}).get('loaded_count', 0)}",
    ]

    disabled_plugins = health.get("plugin_health", {}).get("disabled_plugins", {})
    if disabled_plugins:
        lines.append("  Disabled:")
        for plugin_name, info in disabled_plugins.items():
            detail = info.get("detail", "")
            lines.append(f"    - {plugin_name}: {detail}")
    else:
        lines.append("  Disabled: none")

    lines.append("")
    lines.append("Profiles")
    for profile in health.get("profiles", []):
        missing_required = profile.get("missing_required", [])
        missing_plugins = profile.get("missing_plugins", [])
        if missing_required:
            status = f"blocked: {', '.join(missing_required)}"
        elif missing_plugins:
            status = f"partial: {', '.join(missing_plugins)}"
        else:
            status = "ok"
        lines.append(f"  {profile.get('name')}: {status}")

    return "\n".join(lines)


def _format_tor_line(tor_health: Dict[str, Any]) -> str:
    enabled = bool(tor_health.get("enabled"))
    ready = bool(tor_health.get("ready"))
    proxy_url = tor_health.get("proxy_url", "N/A")

    if not enabled:
        return f"Tor: disabled ({proxy_url})"
    if ready:
        return f"Tor: ok ({proxy_url})"

    issues = tor_health.get("issues", [])
    suffix = f" | {'; '.join(issues)}" if issues else ""
    return f"Tor: error ({proxy_url}){suffix}"
