import json

import requests

from scripts import main as main_module
from utils.auth_session import (
    apply_session_profile_to_prepared_request,
    load_session_profile,
)
from utils.http_session import create_requests_session


def test_load_session_profile_normalizes_token_and_cookie_string(tmp_path):
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "token": "abc123",
                "cookie_string": "PHPSESSID=session123; XSRF-TOKEN=token456",
                "local_storage": {"authToken": "xyz"},
            }
        ),
        encoding="utf-8",
    )

    profile = load_session_profile(session_file)

    assert profile["headers"]["Authorization"] == "Bearer abc123"
    assert profile["cookie_string"] == "PHPSESSID=session123; XSRF-TOKEN=token456"
    assert profile["local_storage"]["authToken"] == "xyz"
    assert {cookie["name"] for cookie in profile["cookies"]} == {"PHPSESSID", "XSRF-TOKEN"}


def test_create_requests_session_applies_headers_and_cookies_from_session_file(tmp_path):
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "headers": {"Authorization": "Bearer secret"},
                "cookies": {"PHPSESSID": "abc123"},
            }
        ),
        encoding="utf-8",
    )

    session = create_requests_session(session_file=str(session_file))

    assert session.headers["Authorization"] == "Bearer secret"
    assert session.cookies.get("PHPSESSID") == "abc123"


def test_apply_session_profile_to_prepared_request_merges_cookie_and_header(tmp_path):
    session_file = tmp_path / "session.json"
    session_file.write_text(
        json.dumps(
            {
                "headers": {"Authorization": "Bearer secret"},
                "cookies": {"PHPSESSID": "abc123"},
            }
        ),
        encoding="utf-8",
    )

    prepared = requests.Request(
        "GET",
        "https://example.test/private",
        headers={"Cookie": "LANG=pt-BR"},
    ).prepare()

    apply_session_profile_to_prepared_request(prepared, session_file=str(session_file))

    assert prepared.headers["Authorization"] == "Bearer secret"
    assert "LANG=pt-BR" in prepared.headers["Cookie"]
    assert "PHPSESSID=abc123" in prepared.headers["Cookie"]


def test_main_passes_session_file_to_run_pipeline(monkeypatch, tmp_path, capsys):
    session_file = tmp_path / "session.json"
    session_file.write_text(json.dumps({"cookies": {"PHPSESSID": "abc123"}}), encoding="utf-8")

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
            return {"run_id": 88, "stages_done": ["stage_recon", "stage_detect"], "errors": 0}

    def fake_run_pipeline(**kwargs):
        captured.update(kwargs)
        return FakeState()

    monkeypatch.setattr(main_module, "PluginManager", FakePluginManager)
    monkeypatch.setattr(main_module, "run_pipeline", fake_run_pipeline)
    monkeypatch.setattr(main_module, "setup_logger", lambda *args, **kwargs: None)
    monkeypatch.setattr(
        main_module.sys,
        "argv",
        ["main.py", "example.com", "--session-file", str(session_file)],
    )

    assert main_module.main() == 0
    output = capsys.readouterr().out
    assert "Sessao autenticada ativa" in output
    assert captured["auth_session_file"] == str(session_file.resolve())
