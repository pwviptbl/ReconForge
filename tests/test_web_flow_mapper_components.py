from types import SimpleNamespace

from core.stages.stage_recon import StageRecon
from core.workflow_state import WorkflowState
from plugins.web_flow_mapper import WebFlowMapperPlugin
from utils.request_utils import rebuild_attack_request
from utils.web_discovery import build_request_nodes, merge_discovery_payload


def _decode_body(prepared):
    body = prepared.body or b""
    if isinstance(body, bytes):
        return body.decode("utf-8", errors="ignore")
    return str(body)


def test_merge_discovery_payload_merges_parameters_and_request_nodes():
    discoveries = {
        "hosts": [],
        "open_ports": [],
        "services": [],
        "technologies": [],
        "forms": [],
        "endpoints": ["https://example.test/app"],
        "parameters": {"query": ["q"]},
        "request_nodes": [{"method": "GET", "url": "https://example.test/app?q=1"}],
        "interactions": [],
        "subdomains": [],
    }

    merge_discovery_payload(
        discoveries,
        {
            "endpoints": ["https://example.test/form"],
            "parameters": {"form": ["email"], "json": ["name"]},
            "request_nodes": [
                {"method": "POST", "url": "https://example.test/form", "data": {"email": "a@b.c"}}
            ],
            "interactions": [{"page_url": "https://example.test/form", "kind": "submit"}],
        },
    )

    assert discoveries["endpoints"] == ["https://example.test/app", "https://example.test/form"]
    assert discoveries["parameters"]["query"] == ["q"]
    assert discoveries["parameters"]["form"] == ["email"]
    assert discoveries["parameters"]["json"] == ["name"]
    assert len(discoveries["request_nodes"]) == 2
    assert len(discoveries["interactions"]) == 1


def test_stage_recon_merges_request_nodes_without_duplicates():
    state = WorkflowState(target="example.test", original_target="https://example.test")
    stage = StageRecon(plugin_manager=None)
    result = SimpleNamespace(
        data={
            "endpoints": ["https://example.test/login"],
            "parameters": {"form": ["login", "senha"]},
            "request_nodes": [
                {
                    "method": "GET",
                    "url": "https://example.test/login?login=teste",
                    "params": {"login": "teste"},
                }
            ],
        }
    )

    stage._merge_discoveries(result, state)
    stage._merge_discoveries(result, state)

    assert state.discoveries["endpoints"] == ["https://example.test/login"]
    assert state.discoveries["parameters"]["form"] == ["login", "senha"]
    assert len(state.discoveries["request_nodes"]) == 1


def test_build_request_nodes_promotes_forms_and_endpoints():
    discoveries = {
        "forms": [
            {
                "url": "https://example.test/upload",
                "action": "https://example.test/upload/save",
                "method": "POST",
                "enctype": "multipart/form-data",
                "inputs": [
                    {"name": "title", "type": "text", "value": "demo"},
                    {"name": "document", "type": "file"},
                ],
            }
        ],
        "endpoints": ["https://example.test/search?q=abc"],
        "request_nodes": [],
    }

    nodes = build_request_nodes(discoveries, "https://example.test", default_headers={"User-Agent": "UnitTest"})

    assert any(node["method"] == "GET" and node["url"] == "https://example.test" for node in nodes)
    assert any(node["method"] == "GET" and node["url"] == "https://example.test/search?q=abc" for node in nodes)
    upload_node = next(node for node in nodes if node["url"] == "https://example.test/upload/save")
    assert upload_node["method"] == "POST"
    assert upload_node["data"]["title"] == "demo"
    assert "document" in upload_node["files"]


def test_rebuild_attack_request_preserves_multipart_file_parts():
    request_node = {
        "method": "POST",
        "url": "https://example.test/upload",
        "headers": {"Content-Type": "multipart/form-data"},
        "data": {"title": "demo"},
        "files": {
            "document": {
                "filename": "probe.txt",
                "content_type": "text/plain",
                "content": "hello",
            }
        },
    }
    injection_point = {
        "location": "BODY_MULTIPART",
        "parameter_name": "title",
        "original_value": "demo",
    }

    prepared = rebuild_attack_request(request_node, injection_point, "PAYLOAD")
    body = _decode_body(prepared)

    assert prepared.method == "POST"
    assert "multipart/form-data" in prepared.headers["Content-Type"]
    assert 'name="title"' in body
    assert "PAYLOAD" in body
    assert 'name="document"' in body


def test_web_flow_mapper_prefers_observed_request_over_dom_request():
    plugin = WebFlowMapperPlugin()
    expected = {
        "method": "POST",
        "url": "https://example.test/auth/login/post",
        "data": {"login": "teste", "senha": "teste"},
        "content_type": "application/x-www-form-urlencoded",
    }
    observed = {
        "method": "GET",
        "url": "https://example.test/auth/login/post?login=teste&senha=teste",
        "params": {"login": "teste", "senha": "teste"},
        "headers": {"X-Test": "1"},
        "response_meta": {"status": 200},
    }

    merged = plugin._merge_observed_request(expected, observed)

    assert merged["method"] == "GET"
    assert merged["url"].endswith("login=teste&senha=teste")
    assert merged["params"]["login"] == "teste"
    assert "data" not in merged or not merged["data"]


def test_web_flow_mapper_collects_file_and_path_parameters():
    plugin = WebFlowMapperPlugin()
    parameters = plugin._collect_parameters(
        forms=[
            {
                "method": "POST",
                "enctype": "multipart/form-data",
                "inputs": [
                    {"name": "description", "type": "text"},
                    {"name": "arquivo", "type": "file"},
                ],
            }
        ],
        request_nodes=[
            {
                "method": "GET",
                "url": "https://example.test/users/42?tab=1",
                "params": {"tab": "1"},
                "files": {},
                "cookies": {"session": "abc"},
            }
        ],
    )

    assert parameters["multipart"] == ["description", "arquivo"]
    assert parameters["file"] == ["arquivo"]
    assert parameters["query"] == ["tab"]
    assert parameters["cookie"] == ["session"]
    assert parameters["path"] == ["42"]
