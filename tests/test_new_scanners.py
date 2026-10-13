"""
Testes dos scanners adicionados nesta linha de trabalho:
Secrets, CORS e SQLi (triagem), além da regressão de filtro de escopo
com porta e do modo incremental do StageDetect.

Usa um servidor HTTP local (127.0.0.1:porta-efêmera), sem rede externa,
exercitando o caminho real de fetch dos plugins — incluindo URLs com
porta explícita, que foi exatamente o caso que regredia.
"""

import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest

from plugins.secrets_scanner_plugin import SecretsScannerPlugin
from plugins.cors_scanner_plugin import CorsScannerPlugin
from plugins.sqli_scanner_plugin import SqliScannerPlugin


class _VulnHandler(BaseHTTPRequestHandler):
    def do_GET(self):  # noqa: N802
        origin = self.headers.get("Origin", "")
        path = self.path

        if path.startswith("/app.js"):
            self._send(
                b"var k='AKIAIOSFODNN7EXAMPLE'; var g='AIzaSyA1234567890abcdefghijklmnopqrstuv';",
                "application/javascript",
            )
            return
        if path.startswith("/api"):
            headers = {}
            if origin:  # CORS inseguro: reflete o Origin + credentials
                headers["Access-Control-Allow-Origin"] = origin
                headers["Access-Control-Allow-Credentials"] = "true"
            self._send(b'{"ok":true}', "application/json", extra=headers)
            return
        if path.startswith("/search"):
            if "%27" in path or "'" in path:
                self._send(b"You have an error in your SQL syntax near ''1'", "text/html")
            else:
                self._send(b"<html>sem resultados</html>", "text/html")
            return
        self._send(b"<html>home</html>", "text/html")

    def _send(self, body, ctype, extra=None):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):  # noqa: A003
        return


@pytest.fixture()
def vuln_server():
    server = HTTPServer(("127.0.0.1", 0), _VulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()


def _ctx(base):
    return {
        "original_target": base,
        "discoveries": {
            "endpoints": [f"{base}/app.js", f"{base}/api"],
            "request_nodes": [
                {"url": f"{base}/api", "method": "GET"},
                {"url": f"{base}/search", "method": "GET", "params": {"q": "1"}},
            ],
        },
    }


def test_secrets_scanner_detects_exposed_key(vuln_server):
    result = SecretsScannerPlugin({"verify_ssl": False}).execute(vuln_server, _ctx(vuln_server))
    vulns = result.data["vulnerabilities"]
    assert result.success
    assert any("AWS" in v["name"] for v in vulns), vulns
    # o segredo deve estar redigido na evidência (não em claro)
    assert all("AKIAIOSFODNN7EXAMPLE" not in (v.get("evidence") or "") for v in vulns)


def test_cors_scanner_detects_origin_reflection(vuln_server):
    result = CorsScannerPlugin({"verify_ssl": False}).execute(vuln_server, _ctx(vuln_server))
    vulns = result.data["vulnerabilities"]
    assert result.success
    assert any("CORS" in v["name"] for v in vulns), vulns
    # reflexão + credentials => High
    assert any(v["severity"] == "High" for v in vulns)


def test_sqli_scanner_detects_error_based(vuln_server):
    result = SqliScannerPlugin({"verify_ssl": False}).execute(vuln_server, _ctx(vuln_server))
    vulns = result.data["vulnerabilities"]
    assert result.success
    assert any("SQL Injection" in v["name"] for v in vulns), vulns


def test_scope_filter_accepts_target_with_port(vuln_server):
    """Regressão: alvo com porta explícita não deve descartar URLs em escopo."""
    scanner = SecretsScannerPlugin({"verify_ssl": False})
    candidates = scanner._collect_candidates(_ctx(vuln_server)["discoveries"], vuln_server)
    assert any("/app.js" in c for c in candidates), candidates
    assert any("/api" in c for c in candidates), candidates


def test_scope_filter_rejects_out_of_scope_host(vuln_server):
    discoveries = {
        "endpoints": [f"{vuln_server}/app.js", "https://dominio-externo.example/leak.js"],
        "request_nodes": [],
    }
    candidates = SecretsScannerPlugin()._collect_candidates(discoveries, vuln_server)
    assert any("/app.js" in c for c in candidates)
    assert not any("dominio-externo" in c for c in candidates)


def test_stage_detect_incremental_reuses_cache():
    """O modo incremental reaproveita o resultado e evita 2a execução."""
    from core.plugin_base import PluginResult
    from core.stages.stage_detect import StageDetect
    from core.storage import Storage
    from core.workflow_state import WorkflowState

    class _PM:
        def __init__(self):
            self.plugins = {"XSSScannerPlugin": object()}
            self.calls = 0

        def execute_plugin(self, name, target, ctx):
            self.calls += 1
            return PluginResult(
                success=True, plugin_name=name, execution_time=0.0,
                data={"vulnerabilities": [{"name": "XSS", "severity": "high",
                                           "url": "https://alvo/x?q=1", "parameter": "q"}]},
            )

    storage = Storage(Path(tempfile.mkdtemp()) / "t.db")
    pm = _PM()
    stage = StageDetect(plugin_manager=pm, plugin_names=["XSSScannerPlugin"],
                        storage=storage, incremental=True)

    def _state():
        s = WorkflowState(target="alvo", original_target="https://alvo")
        s.run_id = storage.create_run("alvo", {}, {})
        return s

    s1 = _state(); stage.execute(s1)
    s2 = _state(); stage.execute(s2)
    assert pm.calls == 1          # 2a execução veio do cache
    assert len(s2.findings) == 1  # e ainda gerou finding a partir do cache
