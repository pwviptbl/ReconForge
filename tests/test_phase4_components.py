from core.browser_attack_engine import BrowserAttackEngine
from core.models import ExploitAttempt, Finding, QueueItem
from core.payload_engine import PayloadEngine
from core.payload_mutator import PayloadMutator
from core.stages import stage_exploit as stage_exploit_module
from plugins.pipelines.xss_pipeline import XssPipeline


def test_payload_mutator_generates_unique_variants():
    mutator = PayloadMutator(max_variants_per_payload=10)
    payloads = mutator.mutate(["<script>alert(1)</script>"], category="xss")

    assert payloads[0] == "<script>alert(1)</script>"
    assert any("%3Cscript%3E" in payload for payload in payloads)
    assert any("s/**/cript" in payload or "scr\x00ipt" in payload for payload in payloads)
    assert len(payloads) == len(set(payloads))


def test_payload_engine_prioritizes_candidate_and_caps_output():
    engine = PayloadEngine()
    payloads = engine.get_payloads(
        context="JS_TEMPLATE",
        category="dom_xss",
        candidate_payload="${alert(1)}",
        max_payloads=4,
    )

    assert payloads[0] == "${alert(1)}"
    assert len(payloads) == 4


def test_browser_attack_engine_returns_failed_attempt_when_unavailable(monkeypatch):
    monkeypatch.setattr("core.browser_attack_engine._PLAYWRIGHT_AVAILABLE", False)

    engine = BrowserAttackEngine()
    item = QueueItem(
        id="queue-1",
        finding_id="finding-1",
        category="dom_xss",
        target="https://example.test",
        endpoint="https://example.test/search",
        method="GET",
        parameter="q",
    )

    attempt = engine.run_attack(item=item, payload="<svg onload=alert(1)>", attempt_number=1)

    assert attempt.status == "failed"
    assert "playwright" in (attempt.error or "").lower()


def test_xss_pipeline_routes_dom_context_to_browser_engine(monkeypatch):
    def fake_run_attack(self, item, payload, attempt_number=1, mode="xss"):
        return ExploitAttempt(
            queue_item_id=item.id,
            attempt_number=attempt_number,
            payload_used=payload,
            executor="BrowserAttackEngine",
            status="impact_proven",
        )

    monkeypatch.setattr(
        "core.browser_attack_engine.BrowserAttackEngine.run_attack",
        fake_run_attack,
    )

    finding = Finding(
        id="finding-dom",
        category="xss",
        target="https://example.test",
        endpoint="https://example.test/app",
        method="GET",
        parameter="q",
        detection_source="UnitTestPlugin",
        context="DOM",
    )
    item = QueueItem.from_finding(finding, priority=2)

    pipeline = XssPipeline()
    attempt = pipeline.run_attempt(item, 1)

    assert attempt.status == "impact_proven"
    assert attempt.executor == "XssPipeline/Browser"


def test_stage_exploit_can_dispatch_dom_xss_category(monkeypatch):
    class FakeExecutor:
        def __init__(self, storage=None, max_attempts=5):
            self.storage = storage

        def execute(self, item):
            return [
                ExploitAttempt(
                    queue_item_id=item.id,
                    attempt_number=1,
                    payload_used="${alert(1)}",
                    executor="DomXssPipeline",
                    status="impact_proven",
                )
            ]

    monkeypatch.setattr(stage_exploit_module, "ExploitExecutor", FakeExecutor)

    finding = Finding(
        id="finding-dom-worker",
        category="dom_xss",
        target="https://example.test",
        endpoint="https://example.test/app",
        method="GET",
        parameter="q",
        detection_source="UnitTestPlugin",
        context="DOM",
        stage="queued",
    )
    item = QueueItem.from_finding(finding, priority=2)
    queue = stage_exploit_module.ExploitQueue()
    queue._memory_queue.append(item)

    pending = queue.get_pending(category="dom_xss")

    assert len(pending) == 1
    assert pending[0].category == "dom_xss"
