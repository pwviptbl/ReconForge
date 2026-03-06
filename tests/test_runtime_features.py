from pathlib import Path

from core.workflow_orchestrator import WorkflowOrchestrator
from scripts import main as main_module
from utils.runtime_health import collect_runtime_health, format_runtime_health_text
from utils.runtime_profiles import resolve_profile_plugins
from utils.web_map import build_web_map_payload, format_web_map_text


def test_build_web_map_payload_filters_static_requests():
    discoveries = {
        "parameters": {"query": ["id"], "form": ["email"]},
        "forms": [
            {
                "url": "https://example.test/login",
                "action": "https://example.test/login/post",
                "method": "POST",
                "inputs": [{"name": "email"}, {"name": "password"}],
            }
        ],
        "request_nodes": [
            {
                "method": "GET",
                "url": "https://example.test/assets/app.js?v=1",
                "params": {"v": "1"},
            },
            {
                "method": "POST",
                "url": "https://example.test/login/post",
                "data": {"email": "demo@example.test", "password": "secret"},
                "ui_action": {"kind": "submit"},
            },
        ],
        "interactions": [{"kind": "submit"}],
    }

    web_map = build_web_map_payload(discoveries)

    assert web_map["summary"]["forms"] == 1
    assert web_map["summary"]["requests_total"] == 2
    assert web_map["summary"]["requests_interesting"] == 1
    assert web_map["parameter_buckets"]["query"] == ["id"]
    assert web_map["requests"][0]["parameter_names"] == ["email", "password"]


def test_format_web_map_text_includes_routes_and_parameters():
    text = format_web_map_text(
        99,
        "example.test",
        {
            "summary": {"forms": 1, "requests_total": 2, "requests_interesting": 1, "interactions": 1},
            "parameter_buckets": {"form": ["email", "password"]},
            "forms": [
                {
                    "method": "POST",
                    "page": "https://example.test/login",
                    "action": "https://example.test/login/post",
                    "fields": ["email", "password"],
                }
            ],
            "requests": [
                {
                    "method": "POST",
                    "url": "https://example.test/login/post",
                    "parameter_names": ["email", "password"],
                    "action": "submit",
                }
            ],
        },
    )

    assert "Run ID: 99" in text
    assert "Parametros" in text
    assert "Formularios" in text
    assert "Requests observadas" in text
    assert "email, password" in text


def test_resolve_profile_plugins_reports_missing_webflow_mapper():
    resolved = resolve_profile_plugins(
        "web-test",
        ["PortScannerPlugin", "WhatWebScannerPlugin", "NucleiScannerPlugin"],
    )

    assert resolved["missing_required"] == ["WebFlowMapperPlugin"]
    assert resolved["recon_plugins"] == ["PortScannerPlugin", "WhatWebScannerPlugin"]
    assert resolved["detect_plugins"] == ["NucleiScannerPlugin"]


def test_collect_runtime_health_marks_profile_as_missing_when_required_plugin_absent():
    class FakePluginManager:
        def get_health_report(self):
            return {
                "loaded_count": 2,
                "loaded_plugins": ["PortScannerPlugin", "NucleiScannerPlugin"],
                "disabled_plugins": {
                    "WebFlowMapperPlugin": {
                        "detail": "dependência 'playwright' não encontrada",
                    }
                },
            }

    health = collect_runtime_health(FakePluginManager())
    profiles = {profile["name"]: profile for profile in health["profiles"]}

    assert profiles["web-map"]["missing_required"] == ["WebFlowMapperPlugin"]
    assert profiles["web-test"]["missing_required"] == ["WebFlowMapperPlugin"]
    assert profiles["infra"]["missing_required"] == []
    assert "NmapScannerPlugin" in profiles["infra"]["missing_plugins"]


def test_format_runtime_health_text_marks_partial_profiles():
    text = format_runtime_health_text(
        {
            "python_executable": "/tmp/python",
            "playwright_module_available": True,
            "plugin_health": {
                "loaded_count": 1,
                "disabled_plugins": {},
            },
            "profiles": [
                {"name": "web-map", "missing_required": [], "missing_plugins": []},
                {"name": "infra", "missing_required": [], "missing_plugins": ["NmapScannerPlugin"]},
                {"name": "web-test", "missing_required": ["WebFlowMapperPlugin"], "missing_plugins": ["WebFlowMapperPlugin"]},
            ],
        }
    )

    assert "web-map: ok" in text
    assert "infra: partial: NmapScannerPlugin" in text
    assert "web-test: blocked: WebFlowMapperPlugin" in text


def test_workflow_orchestrator_runs_report_even_without_findings(tmp_path):
    orchestrator = WorkflowOrchestrator(
        quiet=True,
        data_dir=str(tmp_path / "data"),
        recon_plugins=[],
        detect_plugins=[],
    )
    orchestrator.plugin_manager.plugins = {}

    state = orchestrator.run("example.test")

    assert state.report_path
    assert Path(state.report_path).exists()
    assert state.stage_statuses["stage_detect"].status == "done"
    assert state.stage_statuses["stage_validate"].status == "skipped"
    assert state.stage_statuses["stage_report"].status == "done"


def test_main_show_web_map_path_does_not_shadow_get_config(monkeypatch, capsys):
    class FakePluginManager:
        def __init__(self):
            self.plugins = {}
            self.disabled_plugins = {}

    class FakeStorage:
        def __init__(self, path):
            self.path = path

        def load_run_by_id(self, run_id):
            return None

    monkeypatch.setattr(main_module, "PluginManager", FakePluginManager)
    monkeypatch.setattr(main_module, "Storage", FakeStorage)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "--show-web-map", "52"])

    assert main_module.main() == 1
    output = capsys.readouterr().out
    assert "Run 52 nao encontrado." in output


def test_main_target_defaults_to_web_test_profile(monkeypatch, capsys):
    class FakePluginManager:
        def __init__(self):
            self.plugins = {
                "PortScannerPlugin": object(),
                "WhatWebScannerPlugin": object(),
                "GauCollectorPlugin": object(),
                "KatanaCrawlerPlugin": object(),
                "WebFlowMapperPlugin": object(),
                "XSSScannerPlugin": object(),
                "LFIScannerPlugin": object(),
                "SSRFScannerPlugin": object(),
                "IDORScannerPlugin": object(),
                "HeaderInjectionScannerPlugin": object(),
                "OpenRedirectScannerPlugin": object(),
                "SSTIScannerPlugin": object(),
                "HeaderAnalyzerPlugin": object(),
                "NucleiScannerPlugin": object(),
            }
            self.disabled_plugins = {}

    captured = {}

    class FakeState:
        findings = []
        rejected_findings = []
        evidences = []
        queue_items = []
        attempts = []
        report_path = "data/relatorios/fake.md"
        discoveries = {}
        aborted = False

        def summary(self):
            return {"run_id": 77, "stages_done": ["stage_recon", "stage_detect"], "errors": 0}

    def fake_run_pipeline(**kwargs):
        captured.update(kwargs)
        return FakeState()

    monkeypatch.setattr(main_module, "PluginManager", FakePluginManager)
    monkeypatch.setattr(main_module, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(main_module, "setup_logger", lambda *args, **kwargs: None)
    monkeypatch.setattr(main_module.sys, "argv", ["main.py", "example.com"])

    assert main_module.main() == 0
    output = capsys.readouterr().out
    assert "Perfil padrao ativo: web-test" in output
    assert "Perfil ativo: web-test" in output
    assert captured["target"] == "example.com"
    assert captured["recon_plugins"] == [
        "PortScannerPlugin",
        "WhatWebScannerPlugin",
        "GauCollectorPlugin",
        "KatanaCrawlerPlugin",
        "WebFlowMapperPlugin",
    ]
