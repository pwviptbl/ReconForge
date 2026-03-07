"""
WebFlowMapperPlugin

Mapeia rotas e parametros de aplicacoes web usando um browser real
com interacoes controladas e captura de requests observadas.
"""

from __future__ import annotations

import json
import re
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qs, urljoin, urlparse

from core.plugin_base import PluginResult, WebPlugin
from utils.auth_session import (
    apply_local_storage_init_script,
    load_session_profile,
    playwright_context_options_from_session,
)
from utils.logger import get_logger
from utils.web_discovery import (
    dedupe_request_nodes,
    empty_parameter_buckets,
    merge_parameter_buckets,
    normalize_files,
    normalize_request_node,
    normalize_parameter_buckets,
    query_params_from_url,
    request_node_signature,
)

try:  # pragma: no cover - depende do ambiente
    from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
    from playwright.sync_api import sync_playwright

    _PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - depende do ambiente
    PlaywrightTimeoutError = TimeoutError
    sync_playwright = None
    _PLAYWRIGHT_AVAILABLE = False


_BLOCKED_ACTION_TERMS = (
    "delete",
    "remove",
    "destroy",
    "drop",
    "logout",
    "signout",
    "log out",
    "sair",
    "excluir",
    "apagar",
    "cancelar",
    "desativar",
    "remover",
)

_CAPTCHA_TERMS = ("captcha", "g-recaptcha", "hcaptcha", "turnstile")


class _NetworkCollector:
    def __init__(self, plugin: "WebFlowMapperPlugin"):
        self._plugin = plugin
        self.records: List[Dict[str, Any]] = []
        self._by_request: Dict[int, Dict[str, Any]] = {}

    def mark(self) -> int:
        return len(self.records)

    def request_delta(self, start_idx: int) -> List[Dict[str, Any]]:
        return [dict(item) for item in self.records[start_idx:]]

    def on_request(self, request: Any):
        headers = self._plugin._pw_call(request, "all_headers") or self._plugin._pw_call(request, "headers") or {}
        method = str(self._plugin._pw_call(request, "method") or "GET").upper()
        url = str(self._plugin._pw_call(request, "url") or "")
        record = {
            "method": method,
            "url": url,
            "headers": dict(headers or {}),
            "resource_type": str(self._plugin._pw_call(request, "resource_type") or ""),
            "post_data": self._plugin._pw_call(request, "post_data"),
            "response_meta": {},
            "observed_via": "network",
            "timestamp": time.time(),
        }
        self.records.append(record)
        self._by_request[id(request)] = record

    def on_response(self, response: Any):
        request = self._plugin._pw_call(response, "request")
        if request is None:
            return
        record = self._by_request.get(id(request))
        if not record:
            return
        record["response_meta"] = {
            "status": int(self._plugin._pw_call(response, "status") or 0),
            "url": str(self._plugin._pw_call(response, "url") or record["url"]),
            "headers": dict(
                self._plugin._pw_call(response, "all_headers")
                or self._plugin._pw_call(response, "headers")
                or {}
            ),
        }


class WebFlowMapperPlugin(WebPlugin):
    def __init__(self):
        super().__init__()
        self.description = "Mapeia rotas, formularios e requests com browser real e navegacao controlada"
        self.version = "1.0.0"
        self.supported_targets = ["url", "domain"]
        self.requirements = ["playwright"]
        self.logger = get_logger("WebFlowMapper")
        self.config.update(
            {
                "headless": True,
                "timeout_seconds": 12,
                "max_depth": 3,
                "max_pages": 30,
                "max_actions_per_page": 10,
                "wait_after_action_ms": 1200,
                "submit_forms": True,
                "same_origin_only": True,
                "click_safe_elements": True,
                "follow_redirects": True,
                "launch_args": ["--no-sandbox", "--disable-dev-shm-usage"],
            }
        )

    def validate_target(self, target: str) -> bool:
        return bool(target and target.strip())

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()
        actual_target = context.get("original_target", target)

        if not _PLAYWRIGHT_AVAILABLE:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error="playwright nao esta disponivel no ambiente",
            )

        url = self._normalize_url(actual_target)

        try:
            data = self._run_mapping(url, context, kwargs)
            execution_time = time.time() - start_time
            stats = data.get("web_flow_mapping", {}).get("statistics", {})
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data=data,
                summary=(
                    f"{stats.get('pages_visited', 0)} paginas, "
                    f"{stats.get('request_nodes', 0)} requests, "
                    f"{stats.get('forms', 0)} formularios"
                ),
            )
        except Exception as exc:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=str(exc),
            )

    def _run_mapping(self, start_url: str, context_data: Dict[str, Any], kwargs: Dict[str, Any]) -> Dict[str, Any]:
        max_depth = int(self.config.get("max_depth", 3))
        max_pages = int(self.config.get("max_pages", 30))
        wait_ms = int(self.config.get("wait_after_action_ms", 1200))
        same_origin_only = bool(self.config.get("same_origin_only", True))
        browser_args = list(self.config.get("launch_args", ["--no-sandbox", "--disable-dev-shm-usage"]))

        pages: List[Dict[str, Any]] = []
        forms: List[Dict[str, Any]] = []
        interactions: List[Dict[str, Any]] = []
        request_nodes: List[Dict[str, Any]] = []
        endpoints: Set[str] = set()
        parameters = empty_parameter_buckets()
        queue: List[Tuple[str, int]] = [(start_url, 0)]
        visited: Set[str] = set()
        errors: List[Dict[str, Any]] = []
        origin = urlparse(start_url).netloc

        auth_profile = self._resolve_auth_profile(context_data, kwargs)

        with sync_playwright() as playwright:  # pragma: no cover - depende do browser real
            browser = playwright.chromium.launch(
                headless=bool(self.config.get("headless", True)),
                args=browser_args,
            )
            context_options = {"ignore_https_errors": True}
            context_options.update(playwright_context_options_from_session(session_profile=auth_profile))
            context = browser.new_context(**context_options)
            page = context.new_page()

            collector = _NetworkCollector(self)
            page.on("request", collector.on_request)
            page.on("response", collector.on_response)
            page.on("dialog", self._handle_dialog)

            self._apply_authentication(context, page, start_url, auth_profile, kwargs)

            while queue and len(pages) < max_pages:
                current_url, depth = queue.pop(0)
                canonical = self._canonical_url(current_url)
                if canonical in visited:
                    continue

                try:
                    page_result = self._visit_page(
                        page=page,
                        collector=collector,
                        page_url=current_url,
                        depth=depth,
                        wait_ms=wait_ms,
                    )
                except PlaywrightTimeoutError as exc:
                    errors.append({"url": current_url, "depth": depth, "error": f"timeout: {exc}"})
                    continue
                except Exception as exc:
                    errors.append({"url": current_url, "depth": depth, "error": str(exc)})
                    continue

                visited.add(canonical)
                pages.append(page_result["page"])
                forms = self._merge_forms(forms, page_result["forms"])
                interactions.extend(page_result["interactions"])
                request_nodes = dedupe_request_nodes([*request_nodes, *page_result["request_nodes"]])
                endpoints.update(page_result["endpoints"])
                parameters = merge_parameter_buckets(parameters, page_result["parameters"])

                if depth >= max_depth:
                    continue
                for next_url in page_result["next_urls"]:
                    normalized = self._normalize_follow_url(next_url, current_url)
                    if not normalized:
                        continue
                    if same_origin_only and urlparse(normalized).netloc != origin:
                        continue
                    next_canonical = self._canonical_url(normalized)
                    if next_canonical not in visited and all(self._canonical_url(item[0]) != next_canonical for item in queue):
                        queue.append((normalized, depth + 1))

            browser.close()

        parameters = merge_parameter_buckets(parameters, self._collect_parameters(forms, request_nodes))
        request_nodes = dedupe_request_nodes(request_nodes)
        interactions = self._dedupe_interactions(interactions)
        endpoints = {url for url in endpoints if isinstance(url, str) and url.startswith(("http://", "https://"))}

        web_flow_mapping = {
            "target": start_url,
            "pages": pages,
            "forms_found": forms,
            "request_nodes": request_nodes,
            "interactions": interactions,
            "parameters_discovered": parameters,
            "errors": errors,
            "statistics": {
                "pages_visited": len(pages),
                "forms": len(forms),
                "request_nodes": len(request_nodes),
                "interactions": len(interactions),
                "endpoints": len(endpoints),
                "errors": len(errors),
            },
        }

        return {
            "web_flow_mapping": web_flow_mapping,
            "forms": forms,
            "endpoints": sorted(endpoints),
            "parameters": parameters,
            "request_nodes": request_nodes,
            "interactions": interactions,
        }

    def _visit_page(
        self,
        page: Any,
        collector: _NetworkCollector,
        page_url: str,
        depth: int,
        wait_ms: int,
    ) -> Dict[str, Any]:
        nav_mark = collector.mark()
        page.goto(page_url, wait_until="domcontentloaded", timeout=int(self.config.get("timeout_seconds", 12) * 1000))
        page.wait_for_timeout(wait_ms)

        self._ensure_rf_ids(page)
        snapshot = self._extract_snapshot(page, page_url)
        initial_records = collector.request_delta(nav_mark)
        initial_nodes = self._records_to_request_nodes(
            initial_records,
            source_page=page_url,
            ui_action={"kind": "navigate", "label": page_url},
        )

        forms = list(snapshot["forms"])
        interactions: List[Dict[str, Any]] = []
        request_nodes: List[Dict[str, Any]] = list(initial_nodes)
        endpoints = set(snapshot["endpoints"])
        next_urls = list(snapshot["links"])

        action_budget = int(self.config.get("max_actions_per_page", 10))
        form_actions = snapshot["form_submits"]
        click_actions = snapshot["click_actions"]
        executed = 0

        for form in form_actions:
            if executed >= action_budget:
                break
            action_result = self._execute_form_submit(page, collector, page_url, form, wait_ms)
            interactions.append(action_result["interaction"])
            request_nodes = dedupe_request_nodes([*request_nodes, *action_result["request_nodes"]])
            forms = self._merge_forms(forms, action_result["forms"])
            endpoints.update(action_result["endpoints"])
            next_urls.extend(action_result["links"])
            executed += 1

        if self.config.get("click_safe_elements", True):
            for action in click_actions:
                if executed >= action_budget:
                    break
                action_result = self._execute_click_action(page, collector, page_url, action, wait_ms)
                interactions.append(action_result["interaction"])
                request_nodes = dedupe_request_nodes([*request_nodes, *action_result["request_nodes"]])
                forms = self._merge_forms(forms, action_result["forms"])
                endpoints.update(action_result["endpoints"])
                next_urls.extend(action_result["links"])
                executed += 1

        page_record = {
            "url": page_url,
            "depth": depth,
            "title": snapshot["title"],
            "links": snapshot["link_details"],
            "forms": snapshot["forms"],
            "actions": snapshot["click_actions"] + snapshot["form_submits"],
            "request_count": len(initial_nodes),
        }

        return {
            "page": page_record,
            "forms": forms,
            "interactions": interactions,
            "request_nodes": request_nodes,
            "parameters": self._collect_parameters(forms, request_nodes),
            "endpoints": list(endpoints),
            "next_urls": self._dedupe_urls(next_urls),
        }

    def _execute_form_submit(
        self,
        page: Any,
        collector: _NetworkCollector,
        page_url: str,
        form: Dict[str, Any],
        wait_ms: int,
    ) -> Dict[str, Any]:
        page.goto(page_url, wait_until="domcontentloaded", timeout=int(self.config.get("timeout_seconds", 12) * 1000))
        page.wait_for_timeout(150)
        self._ensure_rf_ids(page)
        interaction = {
            "page_url": page_url,
            "kind": "submit",
            "label": form.get("submit_label") or form.get("action") or "",
            "rf_id": form.get("rf_id"),
            "status": "skipped",
            "reason": "",
            "request_count": 0,
            "final_url": page_url,
            "feedback_text": "",
        }

        if form.get("has_captcha"):
            interaction["reason"] = "captcha_detectado"
            return {"interaction": interaction, "request_nodes": [], "forms": [], "endpoints": [], "links": []}

        if self._is_blocked_action(form.get("submit_label", "")) or self._is_blocked_action(form.get("action", "")):
            interaction["reason"] = "acao_bloqueada"
            return {"interaction": interaction, "request_nodes": [], "forms": [], "endpoints": [], "links": []}

        if not self.config.get("submit_forms", True):
            interaction["reason"] = "submit_desabilitado"
            return {"interaction": interaction, "request_nodes": [], "forms": [], "endpoints": [], "links": []}

        form_selector = f'[data-rf-id="{form["rf_id"]}"]'
        form_locator = page.locator(form_selector)
        if form_locator.count() == 0:
            interaction["reason"] = "formulario_nao_encontrado"
            return {"interaction": interaction, "request_nodes": [], "forms": [], "endpoints": [], "links": []}

        prepared_form = self._fill_form(form_locator, form)
        start_idx = collector.mark()

        try:
            if form.get("submit_rf_id"):
                page.locator(f'[data-rf-id="{form["submit_rf_id"]}"]').first.click(timeout=2000)
            else:
                form_locator.evaluate(
                    """(el) => {
                        if (typeof el.requestSubmit === 'function') {
                            el.requestSubmit();
                        } else {
                            el.submit();
                        }
                    }"""
                )
            page.wait_for_timeout(wait_ms)
            interaction["status"] = "executed"
        except Exception as exc:
            interaction["status"] = "error"
            interaction["reason"] = str(exc)
            return {"interaction": interaction, "request_nodes": [], "forms": [], "endpoints": [], "links": []}

        page.wait_for_timeout(150)
        self._ensure_rf_ids(page)
        records = collector.request_delta(start_idx)
        form_node = self._form_to_request_node(form, prepared_form)
        nodes = self._records_to_request_nodes(
            records,
            source_page=page_url,
            ui_action={"kind": "submit", "label": form.get("submit_label", "")},
            expected_request=form_node,
        )
        if not nodes and form_node:
            nodes = [form_node]

        post_snapshot = self._extract_snapshot(page, page.url)
        interaction["request_count"] = len(nodes)
        interaction["final_url"] = page.url
        interaction["feedback_text"] = self._extract_feedback_text(page)

        updated_forms = self._attach_observed_request(post_snapshot["forms"], nodes)
        observed_endpoints = set(post_snapshot["endpoints"])
        observed_endpoints.add(page.url)
        for node in nodes:
            observed_endpoints.add(node.get("url"))

        return {
            "interaction": interaction,
            "request_nodes": nodes,
            "forms": updated_forms,
            "endpoints": list(observed_endpoints),
            "links": post_snapshot["links"],
        }

    def _execute_click_action(
        self,
        page: Any,
        collector: _NetworkCollector,
        page_url: str,
        action: Dict[str, Any],
        wait_ms: int,
    ) -> Dict[str, Any]:
        page.goto(page_url, wait_until="domcontentloaded", timeout=int(self.config.get("timeout_seconds", 12) * 1000))
        page.wait_for_timeout(150)
        self._ensure_rf_ids(page)

        interaction = {
            "page_url": page_url,
            "kind": "click",
            "label": action.get("label") or action.get("text") or "",
            "rf_id": action.get("rf_id"),
            "status": "skipped",
            "reason": "",
            "request_count": 0,
            "final_url": page_url,
            "feedback_text": "",
        }

        if self._is_blocked_action(action.get("label", "")) or self._is_blocked_action(action.get("href", "")):
            interaction["reason"] = "acao_bloqueada"
            return {"interaction": interaction, "request_nodes": [], "forms": [], "endpoints": [], "links": []}

        if action.get("form_rf_id"):
            form_locator = page.locator(f'[data-rf-id="{action["form_rf_id"]}"]')
            if form_locator.count():
                snapshot = self._extract_snapshot(page, page_url)
                form = next((item for item in snapshot["forms"] if item["rf_id"] == action["form_rf_id"]), None)
                if form:
                    self._fill_form(form_locator, form)

        start_idx = collector.mark()
        try:
            page.locator(f'[data-rf-id="{action["rf_id"]}"]').first.click(timeout=2000)
            page.wait_for_timeout(wait_ms)
            interaction["status"] = "executed"
        except Exception as exc:
            interaction["status"] = "error"
            interaction["reason"] = str(exc)
            return {"interaction": interaction, "request_nodes": [], "forms": [], "endpoints": [], "links": []}

        self._ensure_rf_ids(page)
        records = collector.request_delta(start_idx)
        nodes = self._records_to_request_nodes(
            records,
            source_page=page_url,
            ui_action={"kind": "click", "label": action.get("label", "")},
        )
        post_snapshot = self._extract_snapshot(page, page.url)

        interaction["request_count"] = len(nodes)
        interaction["final_url"] = page.url
        interaction["feedback_text"] = self._extract_feedback_text(page)

        observed_endpoints = set(post_snapshot["endpoints"])
        observed_endpoints.add(page.url)
        for node in nodes:
            observed_endpoints.add(node.get("url"))

        return {
            "interaction": interaction,
            "request_nodes": nodes,
            "forms": post_snapshot["forms"],
            "endpoints": list(observed_endpoints),
            "links": post_snapshot["links"],
        }

    def _extract_snapshot(self, page: Any, page_url: str) -> Dict[str, Any]:
        self._ensure_rf_ids(page)
        snapshot = page.evaluate(
            """
            (currentUrl) => {
                const textOf = (el) => (el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim();
                const hasCaptcha = (form) => {
                    const terms = ['captcha', 'g-recaptcha', 'hcaptcha', 'turnstile'];
                    return terms.some((term) =>
                        form.innerHTML.toLowerCase().includes(term) ||
                        Array.from(form.elements).some((el) =>
                            (el.name || '').toLowerCase().includes(term) ||
                            (el.id || '').toLowerCase().includes(term) ||
                            (el.className || '').toLowerCase().includes(term)
                        )
                    );
                };
                const forms = Array.from(document.forms).map((form) => {
                    const submit = Array.from(form.elements).find((el) => {
                        const tag = (el.tagName || '').toLowerCase();
                        const type = (el.type || '').toLowerCase();
                        return (tag === 'button' && (type === 'submit' || type === '')) || type === 'submit';
                    });
                    return {
                        rf_id: form.dataset.rfId || '',
                        url: currentUrl,
                        action: form.action || currentUrl,
                        method: (form.method || 'GET').toUpperCase(),
                        enctype: form.enctype || 'application/x-www-form-urlencoded',
                        has_captcha: hasCaptcha(form),
                        submit_rf_id: submit ? (submit.dataset.rfId || '') : '',
                        submit_label: submit ? textOf(submit) || submit.value || '' : '',
                        inputs: Array.from(form.elements).map((el) => {
                            const tag = (el.tagName || '').toLowerCase();
                            const type = (el.type || '').toLowerCase();
                            const options = tag === 'select'
                                ? Array.from(el.options || []).map((opt) => ({ value: opt.value, text: (opt.textContent || '').trim() }))
                                : [];
                            return {
                                rf_id: el.dataset.rfId || '',
                                tag,
                                type,
                                name: el.name || '',
                                id: el.id || '',
                                value: el.value || '',
                                placeholder: el.placeholder || '',
                                required: !!el.required,
                                disabled: !!el.disabled,
                                accept: el.accept || '',
                                checked: !!el.checked,
                                options,
                            };
                        }),
                    };
                });

                const links = Array.from(document.querySelectorAll('a[href]')).map((link) => ({
                    rf_id: link.dataset.rfId || '',
                    href: link.href || '',
                    text: textOf(link),
                }));

                const clickActions = Array.from(document.querySelectorAll('a, button, input[type="button"], [role="button"], [onclick]'))
                    .map((el) => ({
                        rf_id: el.dataset.rfId || '',
                        tag: (el.tagName || '').toLowerCase(),
                        type: (el.type || '').toLowerCase(),
                        role: el.getAttribute('role') || '',
                        href: el.href || '',
                        label: textOf(el) || el.value || el.getAttribute('aria-label') || '',
                        form_rf_id: el.form ? (el.form.dataset.rfId || '') : '',
                    }))
                    .filter((item) => !item.form_rf_id && (!item.href || item.href === currentUrl || item.href.endsWith('#') || item.href.includes('javascript:') || item.tag !== 'a'));

                return {
                    title: document.title || '',
                    forms,
                    link_details: links,
                    links: links.map((item) => item.href).filter(Boolean),
                    form_submits: forms,
                    click_actions: clickActions.filter((item) => item.rf_id),
                };
            }
            """,
            page_url,
        )

        endpoints = {page_url}
        for form in snapshot["forms"]:
            if form.get("action"):
                endpoints.add(form["action"])
        for link in snapshot["link_details"]:
            href = link.get("href")
            if href and href.startswith(("http://", "https://")):
                endpoints.add(href)

        snapshot["endpoints"] = sorted(endpoints)
        return snapshot

    def _fill_form(self, form_locator: Any, form: Dict[str, Any]) -> Dict[str, Any]:
        prepared = {"params": {}, "data": {}, "json": {}, "files": {}}
        for field in form.get("inputs", []):
            field_type = str(field.get("type") or "").lower()
            tag = str(field.get("tag") or "").lower()
            name = field.get("name")
            rf_id = field.get("rf_id")
            if not rf_id or not name:
                continue
            if field.get("disabled"):
                continue
            if field_type in {"submit", "button", "reset"} or tag == "fieldset":
                continue

            locator = form_locator.locator(f'[data-rf-id="{rf_id}"]')
            if locator.count() == 0:
                continue

            if field_type == "file":
                dummy_meta = self._dummy_file_for_field(field)
                locator.set_input_files(dummy_meta["path"])
                field["file_template"] = dummy_meta
                prepared["files"][name] = dummy_meta
                continue

            value = self._value_for_field(field)
            if tag == "select":
                if field.get("options"):
                    option_value = self._select_value(field.get("options") or [])
                    if option_value is not None:
                        locator.select_option(option_value)
                        value = option_value
            elif field_type == "checkbox":
                if field.get("required"):
                    locator.check()
                    value = "on"
                elif field.get("checked"):
                    value = field.get("value", "on")
                else:
                    continue
            elif field_type == "radio":
                locator.check()
            else:
                locator.fill(value)

            field["value"] = value
            prepared["data"][name] = value

        if form.get("method", "GET").upper() == "GET":
            prepared["params"] = dict(prepared["data"])
            prepared["data"] = {}
        return prepared

    def _form_to_request_node(self, form: Dict[str, Any], prepared_form: Dict[str, Any]) -> Dict[str, Any]:
        method = str(form.get("method") or "GET").upper()
        content_type = form.get("enctype") or "application/x-www-form-urlencoded"
        node: Dict[str, Any] = {
            "method": method,
            "url": form.get("action") or form.get("url"),
            "content_type": content_type,
            "source_page": form.get("url"),
            "headers": {},
            "files": normalize_files(prepared_form.get("files")),
            "ui_action": {"kind": "submit", "label": form.get("submit_label", "")},
            "observed_via": "form",
        }
        if method == "GET":
            node["params"] = prepared_form.get("params") or {}
        elif "json" in content_type:
            node["json"] = prepared_form.get("data") or {}
        else:
            node["data"] = prepared_form.get("data") or {}
        return normalize_request_node(node)

    def _records_to_request_nodes(
        self,
        records: List[Dict[str, Any]],
        *,
        source_page: str,
        ui_action: Dict[str, Any],
        expected_request: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        nodes: List[Dict[str, Any]] = []
        expected_signature = request_node_signature(expected_request) if expected_request else ""
        expected_url = (expected_request or {}).get("url", "")

        for record in records:
            if not self._is_request_interesting(record):
                continue
            node = self._record_to_request_node(record, source_page=source_page, ui_action=ui_action)
            if not node:
                continue
            if expected_request and (node.get("url") == expected_url or expected_signature == request_node_signature(node)):
                node = self._merge_observed_request(expected_request, node)
            nodes.append(node)

        if expected_request and not any(node.get("url") == expected_url for node in nodes):
            nodes.append(expected_request)

        return dedupe_request_nodes(nodes)

    def _record_to_request_node(
        self,
        record: Dict[str, Any],
        *,
        source_page: str,
        ui_action: Dict[str, Any],
    ) -> Optional[Dict[str, Any]]:
        url = record.get("url")
        if not isinstance(url, str) or not url.startswith(("http://", "https://")):
            return None

        headers = dict(record.get("headers") or {})
        content_type = (
            headers.get("content-type")
            or headers.get("Content-Type")
            or ""
        )
        node: Dict[str, Any] = {
            "method": str(record.get("method") or "GET").upper(),
            "url": url,
            "headers": headers,
            "content_type": content_type,
            "source_page": source_page,
            "ui_action": ui_action,
            "observed_via": record.get("observed_via") or "network",
            "response_meta": record.get("response_meta") or {},
        }

        query_params = query_params_from_url(url)
        if query_params:
            node["params"] = {key: values[0] if len(values) == 1 else values for key, values in query_params.items()}

        body = record.get("post_data")
        if body:
            if "json" in content_type:
                try:
                    node["json"] = json.loads(body)
                except Exception:
                    node["body"] = body
            elif "application/x-www-form-urlencoded" in content_type:
                parsed = parse_qs(body, keep_blank_values=True)
                node["data"] = {key: values[0] if len(values) == 1 else values for key, values in parsed.items()}
            else:
                node["body"] = body

        return normalize_request_node(node)

    def _merge_observed_request(self, expected_request: Dict[str, Any], observed_request: Dict[str, Any]) -> Dict[str, Any]:
        merged = dict(expected_request or {})
        merged.update(
            {
                "method": observed_request.get("method", merged.get("method")),
                "url": observed_request.get("url", merged.get("url")),
                "headers": observed_request.get("headers") or merged.get("headers") or {},
                "content_type": observed_request.get("content_type") or merged.get("content_type"),
                "response_meta": observed_request.get("response_meta") or merged.get("response_meta") or {},
                "observed_via": "network",
            }
        )
        if observed_request.get("params") is not None:
            merged["params"] = observed_request.get("params") or {}
            if merged.get("method") == "GET":
                merged.pop("data", None)
                merged.pop("json", None)
        if observed_request.get("data") is not None:
            merged["data"] = observed_request.get("data")
        if observed_request.get("json") is not None:
            merged["json"] = observed_request.get("json")
        if observed_request.get("body") is not None:
            merged["body"] = observed_request.get("body")
        return normalize_request_node(merged)

    def _attach_observed_request(
        self,
        forms: List[Dict[str, Any]],
        request_nodes: List[Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        if not request_nodes:
            return forms
        updated: List[Dict[str, Any]] = []
        for form in forms:
            match = next((node for node in request_nodes if node.get("url") == form.get("action")), None)
            if match:
                enriched = dict(form)
                enriched["observed_request"] = match
                enriched["observed_via"] = "network"
                updated.append(enriched)
            else:
                updated.append(form)
        return updated

    def _collect_parameters(
        self,
        forms: List[Dict[str, Any]],
        request_nodes: List[Dict[str, Any]],
    ) -> Dict[str, List[str]]:
        parameters = empty_parameter_buckets()
        for form in forms:
            enctype = str(form.get("enctype") or "").lower()
            for field in form.get("inputs", []):
                name = field.get("name")
                if not name:
                    continue
                field_type = str(field.get("type") or "").lower()
                if field_type == "file":
                    self._add_parameter(parameters, "file", name)
                    self._add_parameter(parameters, "multipart", name)
                else:
                    bucket = "query" if str(form.get("method", "GET")).upper() == "GET" else "form"
                    if "multipart" in enctype:
                        bucket = "multipart"
                    self._add_parameter(parameters, bucket, name)

        for node in request_nodes:
            for name in (node.get("params") or {}).keys():
                self._add_parameter(parameters, "query", name)
            for name in (node.get("json") or {}).keys():
                self._add_parameter(parameters, "json", name)
            data = node.get("data")
            if isinstance(data, dict):
                bucket = "multipart" if node.get("files") else "form"
                for name in data.keys():
                    self._add_parameter(parameters, bucket, name)
            for name in (node.get("files") or {}).keys():
                self._add_parameter(parameters, "file", name)
            for name in (node.get("cookies") or {}).keys():
                self._add_parameter(parameters, "cookie", name)
            for segment in self._path_parameters(node.get("url", "")):
                self._add_parameter(parameters, "path", segment)
        return parameters

    def _merge_forms(self, existing: List[Dict[str, Any]], incoming: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        merged = list(existing)
        seen = {self._form_signature(item): idx for idx, item in enumerate(existing)}
        for form in incoming:
            signature = self._form_signature(form)
            idx = seen.get(signature)
            if idx is None:
                merged.append(form)
                seen[signature] = len(merged) - 1
                continue
            if form.get("observed_request"):
                current = dict(merged[idx])
                current["observed_request"] = form["observed_request"]
                current["observed_via"] = form.get("observed_via", current.get("observed_via"))
                merged[idx] = current
        return merged

    def _dedupe_interactions(self, interactions: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        deduped: List[Dict[str, Any]] = []
        seen = set()
        for interaction in interactions:
            signature = json.dumps(
                {
                    "page_url": interaction.get("page_url"),
                    "kind": interaction.get("kind"),
                    "label": interaction.get("label"),
                    "rf_id": interaction.get("rf_id"),
                    "final_url": interaction.get("final_url"),
                },
                sort_keys=True,
                ensure_ascii=False,
            )
            if signature in seen:
                continue
            seen.add(signature)
            deduped.append(interaction)
        return deduped

    def _ensure_rf_ids(self, page: Any):
        page.evaluate(
            """
            () => {
                let counter = 0;
                const mark = (selector) => {
                    document.querySelectorAll(selector).forEach((el) => {
                        if (!el.dataset.rfId) {
                            el.dataset.rfId = `rf-${counter++}`;
                        }
                    });
                };
                mark('form');
                mark('input, textarea, select, button, a, [role="button"], [onclick]');
            }
            """
        )

    def _extract_feedback_text(self, page: Any) -> str:
        try:
            text = page.evaluate(
                """
                () => {
                    const selectors = [
                        '.modal',
                        '.bootbox',
                        '.alert',
                        '.error',
                        '.errors',
                        '.help-inline',
                        '.validation-error',
                        '[role="alert"]'
                    ];
                    const texts = [];
                    selectors.forEach((selector) => {
                        document.querySelectorAll(selector).forEach((el) => {
                            const text = (el.innerText || el.textContent || '').replace(/\\s+/g, ' ').trim();
                            if (text) texts.push(text);
                        });
                    });
                    return texts.slice(0, 5).join(' | ');
                }
                """
            )
            return str(text or "")[:500]
        except Exception:
            return ""

    def _resolve_auth_profile(self, context_data: Dict[str, Any], kwargs: Dict[str, Any]) -> Dict[str, Any]:
        session_file = kwargs.get("session_file") or context_data.get("auth_session_file")
        if not session_file:
            return {}
        try:
            return load_session_profile(session_file)
        except Exception as exc:
            self.logger.warning(f"Falha ao carregar sessao autenticada: {exc}")
            return {}

    def _apply_authentication(
        self,
        context: Any,
        page: Any,
        start_url: str,
        auth_profile: Dict[str, Any],
        kwargs: Dict[str, Any],
    ):
        cookies = kwargs.get("cookies") or []
        cookie_string = kwargs.get("cookie_string")
        if cookie_string:
            cookies = [*cookies, *self._parse_cookie_string(cookie_string, start_url)]
        if auth_profile.get("cookies"):
            cookies = [*cookies, *auth_profile.get("cookies", [])]
        if cookies:
            context.add_cookies(cookies)
        local_storage = auth_profile.get("local_storage") or {}
        if local_storage:
            apply_local_storage_init_script(page, local_storage)

    def _parse_cookie_string(self, cookie_string: str, url: str) -> List[Dict[str, Any]]:
        parsed = urlparse(url)
        cookies: List[Dict[str, Any]] = []
        for part in cookie_string.split(";"):
            if "=" not in part:
                continue
            name, value = part.split("=", 1)
            name = name.strip()
            value = value.strip()
            if not name:
                continue
            cookies.append(
                {
                    "name": name,
                    "value": value,
                    "domain": parsed.hostname or parsed.netloc,
                    "path": "/",
                }
            )
        return cookies

    def _dummy_file_for_field(self, field: Dict[str, Any]) -> Dict[str, Any]:
        upload_dir = Path("data") / "tmp" / "webflow_uploads"
        upload_dir.mkdir(parents=True, exist_ok=True)
        name = field.get("name") or field.get("id") or "upload"
        accept = str(field.get("accept") or "").lower()
        ext = ".txt"
        content_type = "text/plain"
        content = "ReconForge upload probe\n"
        if "xml" in accept:
            ext = ".xml"
            content_type = "application/xml"
            content = "<probe>ReconForge</probe>\n"
        elif "json" in accept:
            ext = ".json"
            content_type = "application/json"
            content = '{"probe":"ReconForge"}\n'
        elif "pdf" in accept:
            ext = ".pdf"
            content_type = "application/pdf"
            content = "%PDF-1.4\n% ReconForge\n"
        path = upload_dir / f"{name}{ext}"
        path.write_text(content, encoding="utf-8")
        return {
            "field_name": name,
            "filename": path.name,
            "path": str(path.resolve()),
            "content_type": content_type,
            "content": content,
        }

    def _value_for_field(self, field: Dict[str, Any]) -> str:
        field_type = str(field.get("type") or "").lower()
        name_blob = " ".join(
            [
                str(field.get("name") or ""),
                str(field.get("id") or ""),
                str(field.get("placeholder") or ""),
            ]
        ).lower()
        existing = str(field.get("value") or "")
        if field_type == "hidden" and existing:
            return existing
        if "cnpjcpf" in name_blob or ("cpf" in name_blob and "cnpj" in name_blob):
            return self._valid_cnpj()
        if "cnpj" in name_blob:
            return self._valid_cnpj()
        if "cpf" in name_blob:
            return self._valid_cpf()
        if "cep" in name_blob:
            return "90010-000"
        if "telefone" in name_blob or "phone" in name_blob or "cel" in name_blob:
            return "51999998888"
        if "email" in name_blob:
            return "reconforge@example.com"
        if "senha" in name_blob or "password" in name_blob:
            return "ReconForge!123"
        if any(term in name_blob for term in ("login", "usuario", "user", "username")):
            return "reconforge"
        if any(term in name_blob for term in ("codigo", "code", "token", "rps", "numero", "number")):
            return "123456"
        if field_type in {"number", "range"}:
            return "123"
        if field_type == "email":
            return "reconforge@example.com"
        if field_type == "password":
            return "ReconForge!123"
        if field_type == "search":
            return "teste"
        return existing or "teste"

    def _select_value(self, options: List[Dict[str, str]]) -> Optional[str]:
        for option in options:
            value = str(option.get("value") or "")
            text = str(option.get("text") or "").strip().lower()
            if not value:
                continue
            if text in {"selecione", "selecionar", "select", "escolha"}:
                continue
            return value
        return options[0]["value"] if options else None

    def _handle_dialog(self, dialog: Any):  # pragma: no cover - depende do browser real
        try:
            dialog.accept()
        except Exception:
            pass

    def _normalize_url(self, target: str) -> str:
        if target.startswith(("http://", "https://")):
            return target
        return f"https://{target}"

    def _normalize_follow_url(self, candidate: str, base_url: str) -> Optional[str]:
        if not candidate:
            return None
        if candidate.startswith(("javascript:", "mailto:", "tel:")):
            return None
        normalized = urljoin(base_url, candidate)
        return normalized if normalized.startswith(("http://", "https://")) else None

    def _canonical_url(self, url: str) -> str:
        parsed = urlparse(url or "")
        cleaned = parsed._replace(fragment="")
        return cleaned.geturl()

    def _dedupe_urls(self, urls: List[str]) -> List[str]:
        deduped: List[str] = []
        seen = set()
        for url in urls:
            normalized = self._normalize_follow_url(url, url)
            if not normalized:
                continue
            canonical = self._canonical_url(normalized)
            if canonical in seen:
                continue
            seen.add(canonical)
            deduped.append(normalized)
        return deduped

    def _form_signature(self, form: Dict[str, Any]) -> str:
        key = {
            "url": form.get("url"),
            "action": form.get("action"),
            "method": form.get("method"),
            "inputs": sorted(field.get("name") for field in form.get("inputs", []) if field.get("name")),
        }
        return json.dumps(key, sort_keys=True, ensure_ascii=False)

    def _is_blocked_action(self, text: str) -> bool:
        lowered = str(text or "").lower()
        return any(term in lowered for term in _BLOCKED_ACTION_TERMS)

    def _path_parameters(self, url: str) -> List[str]:
        values: List[str] = []
        for segment in urlparse(url or "").path.split("/"):
            segment = segment.strip()
            if segment and segment.isdigit():
                values.append(segment)
        return values

    def _add_parameter(self, parameters: Dict[str, List[str]], bucket: str, name: str):
        if bucket not in parameters or not name:
            return
        if name not in parameters[bucket]:
            parameters[bucket].append(name)

    def _is_request_interesting(self, record: Dict[str, Any]) -> bool:
        url = str(record.get("url") or "")
        if not url.startswith(("http://", "https://")):
            return False
        resource_type = str(record.get("resource_type") or "").lower()
        if resource_type in {"image", "media", "font", "stylesheet"}:
            return False
        return True

    def _pw_call(self, obj: Any, attr: str, *args) -> Any:
        if obj is None or not hasattr(obj, attr):
            return None
        value = getattr(obj, attr)
        if callable(value):
            try:
                return value(*args)
            except TypeError:
                return value
        return value

    def _valid_cpf(self) -> str:
        digits = [1, 1, 1, 4, 4, 4, 7, 7, 7]
        for factor in (10, 11):
            total = sum(num * (factor - idx) for idx, num in enumerate(digits))
            remainder = (total * 10) % 11
            digits.append(0 if remainder == 10 else remainder)
        return "".join(str(num) for num in digits)

    def _valid_cnpj(self) -> str:
        digits = [1, 1, 2, 2, 2, 3, 3, 0, 0, 0, 1, 8]
        weight_sets = (
            [5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2],
            [6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2],
        )
        for weights in weight_sets:
            total = sum(num * weight for num, weight in zip(digits, weights))
            remainder = total % 11
            digits.append(0 if remainder < 2 else 11 - remainder)
        return "".join(str(num) for num in digits)
