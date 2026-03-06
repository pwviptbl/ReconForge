from pathlib import Path

from core.models import Evidence, ExploitAttempt, Finding, QueueItem
from core.storage import Storage
from core.stages import stage_exploit as stage_exploit_module
from core.stages.stage_evidence import StageEvidence
from core.stages.stage_exploit import StageExploit
from core.stages.stage_report import StageReport
from core.workflow_state import WorkflowState


def _build_finding(category: str, suffix: str, run_id: int = 1) -> Finding:
    return Finding(
        id=f"finding-{suffix}",
        category=category,
        target="https://example.test",
        endpoint=f"https://example.test/{suffix}",
        method="GET",
        parameter="q",
        detection_source="UnitTestPlugin",
        run_id=run_id,
        stage="queued",
    )


def test_stage_exploit_updates_statuses_and_finding_stages(monkeypatch):
    class FakeExecutor:
        def __init__(self, storage=None, max_attempts=5):
            self.storage = storage
            self.max_attempts = max_attempts

        def execute(self, item):
            if item.category == "xss":
                return [
                    ExploitAttempt(
                        queue_item_id=item.id,
                        attempt_number=1,
                        payload_used="<svg onload=alert(1)>",
                        executor="FakeXssPipeline",
                        status="impact_proven",
                    )
                ]
            if item.category == "sqli":
                return [
                    ExploitAttempt(
                        queue_item_id=item.id,
                        attempt_number=1,
                        payload_used="' OR 1=1--",
                        executor="FakeSqliPipeline",
                        status="failed",
                    )
                ]
            return []

    monkeypatch.setattr(stage_exploit_module, "ExploitExecutor", FakeExecutor)

    xss_finding = _build_finding("xss", "xss")
    sqli_finding = _build_finding("sqli", "sqli")
    redirect_finding = _build_finding("open_redirect", "redirect")

    state = WorkflowState(
        target="example.test",
        run_id=1,
        config={"plugins": {"max_parallel": 2}},
        findings=[xss_finding, sqli_finding, redirect_finding],
        queue_items=[
            QueueItem.from_finding(xss_finding, priority=2),
            QueueItem.from_finding(sqli_finding, priority=1),
            QueueItem.from_finding(redirect_finding, priority=4),
        ],
    )

    stage = StageExploit(max_attempts_per_item=2)
    stage.run(state)

    items_by_category = {item.category: item for item in state.queue_items}
    findings_by_category = {finding.category: finding for finding in state.findings}

    assert items_by_category["xss"].status == "done"
    assert items_by_category["sqli"].status == "failed"
    assert items_by_category["open_redirect"].status == "skipped"

    assert findings_by_category["xss"].stage == "exploited"
    assert findings_by_category["sqli"].stage == "exploited"
    assert findings_by_category["open_redirect"].stage == "queued"

    assert [attempt.queue_item_id for attempt in state.attempts] == [
        items_by_category["sqli"].id,
        items_by_category["xss"].id,
    ]


def test_stage_evidence_generates_none_evidence_for_items_without_attempts(tmp_path):
    skipped_finding = _build_finding("open_redirect", "skip", run_id=42)
    failed_finding = _build_finding("sqli", "fail", run_id=42)
    skipped_item = QueueItem.from_finding(skipped_finding, priority=4)
    failed_item = QueueItem.from_finding(failed_finding, priority=1)
    skipped_item.status = "skipped"
    failed_item.status = "failed"

    failed_attempt = ExploitAttempt(
        queue_item_id=failed_item.id,
        attempt_number=1,
        payload_used="' OR 1=1--",
        executor="FakeSqliPipeline",
        request_snapshot="GET /search?q=' OR 1=1--",
        response_snapshot="HTTP/1.1 500",
        status="failed",
    )

    state = WorkflowState(
        target="example.test",
        run_id=42,
        queue_items=[skipped_item, failed_item],
        attempts=[failed_attempt],
    )

    stage = StageEvidence(evidence_dir=tmp_path / "evidencias")
    stage.execute(state)

    evidences_by_item = {evidence.queue_item_id: evidence for evidence in state.evidences}
    skipped_evidence = evidences_by_item[skipped_item.id]
    failed_evidence = evidences_by_item[failed_item.id]

    assert skipped_evidence.proof_level == "none"
    assert failed_evidence.proof_level == "none"
    assert len(skipped_evidence.artifacts) == 1
    assert len(failed_evidence.artifacts) == 1
    assert Path(skipped_evidence.artifacts[0]).exists()
    assert Path(failed_evidence.artifacts[0]).exists()


def test_storage_loaders_return_typed_models(tmp_path):
    storage = Storage(tmp_path / "reconforge.db")
    run_id = storage.create_run("example.test", {}, {})

    finding = _build_finding("xss", "typed", run_id=run_id)
    queue_item = QueueItem.from_finding(finding, priority=2)
    attempt = ExploitAttempt(
        queue_item_id=queue_item.id,
        attempt_number=1,
        payload_used="<script>alert(1)</script>",
        executor="FakeXssPipeline",
        status="partial",
    )
    evidence = Evidence(
        queue_item_id=queue_item.id,
        attempt_id=attempt.id,
        proof_level="partial",
        artifacts=[str(tmp_path / "artifact.json")],
        impact_summary="Payload refletido sem prova de execução.",
    )

    storage.save_queue_item(queue_item)
    storage.save_attempt(attempt)
    storage.save_evidence(evidence)

    loaded_items = storage.load_queue_items(run_id)
    loaded_attempts = storage.load_attempts(queue_item.id)
    loaded_evidences = storage.load_evidences(run_id)

    assert isinstance(loaded_items[0], QueueItem)
    assert isinstance(loaded_attempts[0], ExploitAttempt)
    assert isinstance(loaded_evidences[0], Evidence)
    assert loaded_evidences[0].artifacts == evidence.artifacts


def test_stage_report_json_exposes_web_mapping_summary(tmp_path):
    state = WorkflowState(
        target="example.test",
        run_id=77,
        discoveries={
            "hosts": ["127.0.0.1"],
            "open_ports": [443],
            "services": [],
            "technologies": [],
            "forms": [{"action": "https://example.test/login"}],
            "endpoints": ["https://example.test/login"],
            "parameters": {
                "query": ["next"],
                "form": ["email", "password"],
                "json": [],
                "multipart": [],
                "file": [],
                "cookie": ["session"],
                "path": ["42"],
            },
            "request_nodes": [{
                "method": "POST",
                "url": "https://example.test/login",
                "data": {"email": "user@example.test", "password": "secret"},
                "ui_action": {"kind": "submit", "label": "Entrar"},
            }],
            "interactions": [{"kind": "submit", "page_url": "https://example.test/login"}],
            "subdomains": [],
        },
        executed_plugins=["WebFlowMapperPlugin", "XSSScannerPlugin"],
    )

    stage = StageReport(output_dir=tmp_path / "relatorios")
    stage.run(state)

    json_reports = list((tmp_path / "relatorios" / "run_77").glob("*.json"))
    md_reports = list((tmp_path / "relatorios" / "run_77").glob("*.md"))
    assert len(json_reports) == 1
    assert len(md_reports) == 1

    payload = json_reports[0].read_text(encoding="utf-8")
    markdown = md_reports[0].read_text(encoding="utf-8")
    assert '"WebFlowMapperPlugin"' in payload
    assert '"discovery_summary"' in payload
    assert '"forms": 1' in payload
    assert '"request_nodes": 1' in payload
    assert '"interactions": 1' in payload
    assert '"web_mapping"' in payload
    assert '"parameter_buckets"' in payload
    assert 'https://example.test/login' in payload
    assert '"email"' in payload
    assert '"stage_report"' in payload
    assert '"status": "done"' in payload
    assert "## 🌐 Rotas e Parâmetros Mapeados" in markdown
    assert "Formulários detectados" in markdown
    assert "Requests observadas com parâmetros" in markdown
    assert "| stage_report | ✅ done |" in markdown
