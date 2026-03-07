from utils.ai_reporter import AIReportGenerator


class _FakeState:
    target = "example.test"
    run_id = 101
    evidences = []
    findings = []
    rejected_findings = []
    queue_items = []
    attempts = []
    discoveries = {
        "hosts": [],
        "open_ports": [],
        "services": [],
        "technologies": [],
        "forms": [],
        "endpoints": [],
        "parameters": {},
        "request_nodes": [],
        "interactions": [],
        "subdomains": [],
    }


def test_ai_reporter_skips_when_api_key_missing(monkeypatch):
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)

    result = AIReportGenerator().generate_for_state(_FakeState())

    assert result.generated is False
    assert result.skipped_reason == "api_key_missing"
