from types import SimpleNamespace

from core.plugin_manager import PluginManager
from scripts import main as main_module
from utils.runtime_health import format_runtime_health_text
from utils.tor import get_playwright_proxy_settings


def test_get_playwright_proxy_settings_uses_tor_proxy(monkeypatch):
    monkeypatch.setattr("utils.tor.ensure_tor_ready", lambda **kwargs: None)
    monkeypatch.setattr("utils.tor.tor_proxy_url", lambda: "socks5h://user:pass@127.0.0.1:9050")

    proxy = get_playwright_proxy_settings(use_tor=True)

    assert proxy == {
        "server": "socks5://127.0.0.1:9050",
        "username": "user",
        "password": "pass",
    }


def test_format_runtime_health_text_reports_tor_status():
    text = format_runtime_health_text(
        {
            "python_executable": "/tmp/python",
            "playwright_module_available": True,
            "tor": {
                "enabled": True,
                "proxy_url": "socks5h://127.0.0.1:9050",
                "ready": False,
                "issues": ["proxy indisponivel"],
            },
            "plugin_health": {
                "loaded_count": 0,
                "disabled_plugins": {},
            },
            "profiles": [],
        }
    )

    assert "Tor: error (socks5h://127.0.0.1:9050) | proxy indisponivel" in text


def test_plugin_manager_blocks_incompatible_plugin_in_tor_mode(monkeypatch):
    class PortScannerPlugin:
        def validate_target(self, target):
            return True

        def execute(self, target, context, **kwargs):
            raise AssertionError("nao deveria executar")

    manager = PluginManager.__new__(PluginManager)
    manager.plugins = {"PortScannerPlugin": PortScannerPlugin()}
    manager.logger = SimpleNamespace(info=lambda *a, **k: None)

    monkeypatch.setattr(
        "core.plugin_manager.get_config",
        lambda path, default=None: True if path == "network.tor.enabled" else default,
    )

    result = PluginManager.execute_plugin(manager, "PortScannerPlugin", "example.test", {})

    assert result.success is False
    assert "modo Tor estrito" in (result.error or "")


def test_main_rejects_pipeline_when_tor_not_ready(monkeypatch, capsys):
    class FakePluginManager:
        def __init__(self):
            self.plugins = {}
            self.disabled_plugins = {}

    monkeypatch.setattr(main_module, "PluginManager", FakePluginManager)
    monkeypatch.setattr(
        main_module,
        "collect_tor_status",
        lambda: {
            "enabled": True,
            "ready": False,
            "issues": ["Tor nao esta escutando na porta 9050"],
        },
    )
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "example.com"])

    assert main_module.main() == 2
    output = capsys.readouterr().out
    assert "Modo Tor habilitado" in output
    assert "Tor nao esta escutando na porta 9050" in output
