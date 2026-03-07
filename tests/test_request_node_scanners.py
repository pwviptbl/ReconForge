from types import SimpleNamespace

import requests

from plugins.idor_scanner_plugin import IDORScannerPlugin
from plugins.xss_scanner_plugin import XSSScannerPlugin


def test_xss_scanner_uses_request_nodes_for_post_body(monkeypatch):
    sent_requests = []
    session = requests.Session()

    def fake_send(prepared, timeout=None, **kwargs):
        sent_requests.append(prepared)
        return SimpleNamespace(text="PAYLOAD reflected", headers={}, status_code=200)

    session.send = fake_send

    monkeypatch.setattr(
        "plugins.xss_scanner_plugin.create_requests_session",
        lambda plugin_config=None, **kwargs: session,
    )

    scanner = XSSScannerPlugin({"payloads": ["PAYLOAD"]})
    result = scanner.execute(
        "https://example.test",
        {
            "original_target": "https://example.test",
            "discoveries": {
                "request_nodes": [
                    {
                        "method": "POST",
                        "url": "https://example.test/comment",
                        "data": {"comment": "hello", "post_id": "1"},
                    }
                ]
            },
        },
    )

    assert result.data["tested_count"] >= 2
    assert sent_requests
    body = sent_requests[0].body.decode("utf-8", errors="ignore") if isinstance(sent_requests[0].body, bytes) else str(sent_requests[0].body)
    assert "PAYLOAD" in body


def test_idor_scanner_uses_numeric_values_from_request_nodes(monkeypatch):
    session = requests.Session()

    def fake_send(prepared, timeout=None, **kwargs):
        body = prepared.body.decode("utf-8", errors="ignore") if isinstance(prepared.body, bytes) else str(prepared.body)
        if "user_id=11" in body:
            content = b"B" * 200
        else:
            content = b"A" * 100
        return SimpleNamespace(status_code=200, content=content, headers={}, text=content.decode("ascii", errors="ignore"))

    session.send = fake_send

    monkeypatch.setattr(
        "plugins.idor_scanner_plugin.create_requests_session",
        lambda plugin_config=None, **kwargs: session,
    )

    scanner = IDORScannerPlugin()
    result = scanner.execute(
        "https://example.test",
        {
            "original_target": "https://example.test",
            "discoveries": {
                "request_nodes": [
                    {
                        "method": "POST",
                        "url": "https://example.test/users/update",
                        "data": {"user_id": "10", "name": "demo"},
                    }
                ]
            },
        },
    )

    assert result.data["tested_count"] >= 2
    assert result.data["vulnerabilities"]
