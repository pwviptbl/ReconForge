"""
BrowserAttackEngine — Fase 4

Executa ataques que exigem browser real usando Playwright, com fallback
gracioso quando a dependência não estiver instalada no ambiente.
"""

from __future__ import annotations

import asyncio
import json
import re
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from core.models import ExploitAttempt, QueueItem
from utils.auth_session import (
    load_session_profile,
    playwright_context_options_from_session,
)
from utils.logger import get_logger

try:  # pragma: no cover - depende do ambiente
    from playwright.async_api import TimeoutError as PlaywrightTimeoutError
    from playwright.async_api import async_playwright

    _PLAYWRIGHT_AVAILABLE = True
except ImportError:  # pragma: no cover - depende do ambiente
    async_playwright = None
    PlaywrightTimeoutError = TimeoutError
    _PLAYWRIGHT_AVAILABLE = False


@dataclass
class BrowserAttackConfig:
    headless: bool = True
    record_video: bool = False
    screenshot_on_finish: bool = True
    timeout_seconds: int = 8
    wait_after_inject_ms: int = 1200
    evidence_dir: Path = Path("data") / "evidencias" / "browser"
    credentials: Optional[Dict[str, str]] = None
    launch_args: List[str] = field(
        default_factory=lambda: ["--no-sandbox", "--disable-dev-shm-usage"]
    )

    def __post_init__(self):
        self.evidence_dir = Path(self.evidence_dir)
        self.evidence_dir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_mapping(cls, data: Optional[Dict[str, Any]]) -> "BrowserAttackConfig":
        data = data or {}
        return cls(
            headless=bool(data.get("headless", True)),
            record_video=bool(data.get("record_video", False)),
            screenshot_on_finish=bool(data.get("screenshot_on_finish", True)),
            timeout_seconds=int(data.get("timeout_seconds", 8)),
            wait_after_inject_ms=int(data.get("wait_after_inject_ms", 1200)),
            evidence_dir=Path(data.get("evidence_dir", "data/evidencias/browser")),
            credentials=data.get("credentials"),
            launch_args=list(data.get("launch_args", ["--no-sandbox", "--disable-dev-shm-usage"])),
        )


class BrowserAttackEngine:
    """Ataques assistidos por browser para DOM XSS, CSRF e cenários autenticados."""

    def __init__(self, config: Optional[BrowserAttackConfig] = None):
        self.logger = get_logger("BrowserAttackEngine")
        self.config = config or BrowserAttackConfig()

    @property
    def available(self) -> bool:
        return _PLAYWRIGHT_AVAILABLE

    def run_attack(
        self,
        item: QueueItem,
        payload: str,
        attempt_number: int = 1,
        mode: str = "xss",
    ) -> ExploitAttempt:
        if not self.available:
            return self._failed_attempt(
                item=item,
                payload=payload,
                attempt_number=attempt_number,
                mode=mode,
                error="playwright não instalado no ambiente",
            )

        loop = asyncio.new_event_loop()
        try:
            return loop.run_until_complete(
                self.run_attack_async(
                    item=item,
                    payload=payload,
                    attempt_number=attempt_number,
                    mode=mode,
                )
            )
        finally:
            loop.close()

    async def run_attack_async(
        self,
        item: QueueItem,
        payload: str,
        attempt_number: int = 1,
        mode: str = "xss",
    ) -> ExploitAttempt:
        marker = f"RF_BROWSER_{uuid.uuid4().hex[:10]}"
        instrumented_payload = self._instrument_payload(payload, marker) if mode == "xss" else payload
        request_snapshot = json.dumps(
            {
                "mode": mode,
                "method": item.method,
                "target": item.target,
                "endpoint": item.endpoint,
                "parameter": item.parameter,
                "payload": instrumented_payload,
            },
            ensure_ascii=False,
        )

        try:
            async with async_playwright() as playwright:
                browser = await playwright.chromium.launch(
                    headless=self.config.headless,
                    args=self.config.launch_args,
                )

                run_dir = self.config.evidence_dir / f"run_{item.run_id or 'unknown'}"
                run_dir.mkdir(parents=True, exist_ok=True)
                context_kwargs: Dict[str, Any] = {}
                if self.config.record_video:
                    context_kwargs["record_video_dir"] = str(run_dir)
                auth_profile = self._load_auth_profile(item)
                context_kwargs.update(playwright_context_options_from_session(session_profile=auth_profile))

                context = await browser.new_context(**context_kwargs)
                page = await context.new_page()
                if auth_profile.get("cookies"):
                    await context.add_cookies(auth_profile["cookies"])
                if auth_profile.get("local_storage"):
                    await page.add_init_script(
                        """
                        (items) => {
                            const data = items || {};
                            for (const [key, value] of Object.entries(data)) {
                                try {
                                    window.localStorage.setItem(key, String(value));
                                } catch (error) {
                                }
                            }
                        }
                        """,
                        auth_profile["local_storage"],
                    )

                console_messages: List[str] = []
                dialog_messages: List[str] = []
                marker_triggered = asyncio.Event()

                page.on(
                    "console",
                    lambda msg: self._on_console(msg.text, marker, console_messages, marker_triggered),
                )
                page.on(
                    "dialog",
                    lambda dialog: asyncio.create_task(
                        self._on_dialog(dialog, marker, dialog_messages, marker_triggered)
                    ),
                )

                if self.config.credentials:
                    await self._authenticate(page, item)

                network_result = await self._perform_request(
                    page=page,
                    item=item,
                    payload=instrumented_payload,
                    mode=mode,
                )
                await page.wait_for_timeout(self.config.wait_after_inject_ms)

                page_content = await page.content()
                screenshot_path = await self._capture_screenshot(
                    page=page,
                    item=item,
                    attempt_number=attempt_number,
                )

                status = self._classify_result(
                    mode=mode,
                    marker=marker,
                    marker_triggered=marker_triggered.is_set(),
                    page_content=page_content,
                    console_messages=console_messages,
                    dialog_messages=dialog_messages,
                    network_result=network_result,
                )

                response_snapshot = json.dumps(
                    {
                        "mode": mode,
                        "status": network_result.get("status", 0),
                        "url": network_result.get("url") or page.url,
                        "body_preview": network_result.get("body", "")[:4096],
                        "page_preview": page_content[:4096],
                        "console": console_messages,
                        "dialogs": dialog_messages,
                        "artifacts": [screenshot_path] if screenshot_path else [],
                    },
                    ensure_ascii=False,
                )

                await context.close()
                await browser.close()

                return ExploitAttempt(
                    queue_item_id=item.id,
                    attempt_number=attempt_number,
                    payload_used=instrumented_payload,
                    executor="BrowserAttackEngine",
                    request_snapshot=request_snapshot,
                    response_snapshot=response_snapshot,
                    status=status,
                )

        except PlaywrightTimeoutError as exc:
            return self._failed_attempt(
                item=item,
                payload=instrumented_payload,
                attempt_number=attempt_number,
                mode=mode,
                error=f"timeout no browser: {exc}",
                request_snapshot=request_snapshot,
            )
        except Exception as exc:  # pragma: no cover - depende do browser real
            return self._failed_attempt(
                item=item,
                payload=instrumented_payload,
                attempt_number=attempt_number,
                mode=mode,
                error=str(exc),
                request_snapshot=request_snapshot,
            )

    @staticmethod
    def _on_console(
        text: str,
        marker: str,
        console_messages: List[str],
        marker_triggered: asyncio.Event,
    ) -> None:
        console_messages.append(text)
        if marker in text:
            marker_triggered.set()

    async def _on_dialog(
        self,
        dialog: Any,
        marker: str,
        dialog_messages: List[str],
        marker_triggered: asyncio.Event,
    ) -> None:
        dialog_messages.append(dialog.message)
        if marker in dialog.message:
            marker_triggered.set()
        await dialog.accept()

    async def _authenticate(self, page: Any, item: QueueItem) -> None:
        credentials = self.config.credentials or {}
        login_url = credentials.get("login_url") or item.target or item.endpoint
        if not login_url:
            return

        await page.goto(login_url, wait_until="domcontentloaded", timeout=self.config.timeout_seconds * 1000)

        username = credentials.get("username")
        password = credentials.get("password")
        if not username or not password:
            return

        username_selector = credentials.get("username_selector") or 'input[type="email"], input[name="username"], input[name="email"], input[type="text"]'
        password_selector = credentials.get("password_selector") or 'input[type="password"]'
        submit_selector = credentials.get("submit_selector") or 'button[type="submit"], input[type="submit"]'

        try:
            await page.locator(username_selector).first.fill(username)
            await page.locator(password_selector).first.fill(password)
            await page.locator(submit_selector).first.click()
            await page.wait_for_timeout(1000)
        except Exception as exc:
            self.logger.debug(f"Autenticação heurística não concluída: {exc}")

    def _load_auth_profile(self, item: QueueItem) -> Dict[str, Any]:
        if getattr(item, "auth_session", None):
            return item.auth_session
        session_file = str(getattr(item, "auth_session_file", "") or "")
        if not session_file:
            return {}
        try:
            profile = load_session_profile(session_file)
            item.auth_session = profile
            return profile
        except Exception as exc:
            self.logger.debug(f"Falha ao carregar sessao do browser attack: {exc}")
            return {}

    async def _perform_request(
        self,
        page: Any,
        item: QueueItem,
        payload: str,
        mode: str,
    ) -> Dict[str, Any]:
        timeout_ms = self.config.timeout_seconds * 1000
        url = item.endpoint or item.target
        method = (item.method or "GET").upper()

        if method == "GET":
            target_url = self._build_url(url, item.parameter, payload)
            response = await page.goto(
                target_url,
                wait_until="domcontentloaded",
                timeout=timeout_ms,
            )
            return {
                "status": response.status if response else 0,
                "url": page.url,
                "body": await page.content(),
                "mode": mode,
            }

        await page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        script = """
            async ({url, method, parameter, payload}) => {
                const body = new URLSearchParams();
                if (parameter) {
                    body.set(parameter, payload);
                } else if (payload) {
                    body.set("payload", payload);
                }

                const response = await fetch(url, {
                    method,
                    credentials: "include",
                    headers: {"Content-Type": "application/x-www-form-urlencoded"},
                    body: method === "GET" ? undefined : body.toString(),
                });
                const text = await response.text();
                document.open();
                document.write(text);
                document.close();
                return {status: response.status, url: response.url, text};
            }
        """
        result = await page.evaluate(
            script,
            {
                "url": url,
                "method": method,
                "parameter": item.parameter,
                "payload": payload,
            },
        )
        return {
            "status": result.get("status", 0),
            "url": result.get("url", page.url),
            "body": result.get("text", ""),
            "mode": mode,
        }

    async def _capture_screenshot(
        self,
        page: Any,
        item: QueueItem,
        attempt_number: int,
    ) -> str:
        if not self.config.screenshot_on_finish:
            return ""

        run_dir = self.config.evidence_dir / f"run_{item.run_id or 'unknown'}"
        run_dir.mkdir(parents=True, exist_ok=True)
        screenshot_path = run_dir / f"browser_{item.id[:8]}_att{attempt_number}.png"
        try:
            await page.screenshot(path=str(screenshot_path), full_page=True)
            return str(screenshot_path.resolve())
        except Exception as exc:
            self.logger.debug(f"Falha ao capturar screenshot: {exc}")
            return ""

    @staticmethod
    def _build_url(url: str, parameter: str, payload: str) -> str:
        if not parameter:
            return url

        parts = urlsplit(url)
        query = dict(parse_qsl(parts.query, keep_blank_values=True))
        query[parameter] = payload
        return urlunsplit(
            (parts.scheme, parts.netloc, parts.path, urlencode(query, doseq=True), parts.fragment)
        )

    @staticmethod
    def _instrument_payload(payload: str, marker: str) -> str:
        if not payload:
            return f"<script>console.log('{marker}')</script>"

        replacement = f"console.log('{marker}')"
        instrumented = re.sub(r"alert\s*\([^)]*\)", replacement, payload, flags=re.IGNORECASE)
        instrumented = re.sub(r"confirm\s*\([^)]*\)", replacement, instrumented, flags=re.IGNORECASE)
        instrumented = re.sub(r"prompt\s*\([^)]*\)", replacement, instrumented, flags=re.IGNORECASE)

        if instrumented != payload:
            return instrumented

        if "</script>" in instrumented.lower():
            return re.sub(
                r"</script>",
                f"{replacement}</script>",
                instrumented,
                count=1,
                flags=re.IGNORECASE,
            )
        return instrumented

    @staticmethod
    def _classify_result(
        mode: str,
        marker: str,
        marker_triggered: bool,
        page_content: str,
        console_messages: List[str],
        dialog_messages: List[str],
        network_result: Dict[str, Any],
    ) -> str:
        body = (network_result.get("body") or "") + page_content
        body_lower = body.lower()
        status_code = int(network_result.get("status") or 0)

        if mode == "xss":
            if marker_triggered or any(marker in entry for entry in console_messages + dialog_messages):
                return "impact_proven"
            if marker in body:
                return "partial"
            if any(keyword in body_lower for keyword in ("<script", "onerror=", "onload=", "javascript:")):
                return "partial"
            return "failed"

        failure_markers = ("csrf", "forbidden", "unauthorized", "invalid token")
        success_markers = ("success", "updated", "deleted", "saved", "created", "completed")

        if status_code in (401, 403, 422) or any(marker in body_lower for marker in failure_markers):
            return "failed"
        if status_code in (200, 201, 202, 204) and any(marker in body_lower for marker in success_markers):
            return "impact_proven"
        if status_code in (200, 201, 202, 204):
            return "partial"
        return "failed"

    @staticmethod
    def _failed_attempt(
        item: QueueItem,
        payload: str,
        attempt_number: int,
        mode: str,
        error: str,
        request_snapshot: str = "",
    ) -> ExploitAttempt:
        return ExploitAttempt(
            queue_item_id=item.id,
            attempt_number=attempt_number,
            payload_used=payload,
            executor="BrowserAttackEngine",
            request_snapshot=request_snapshot or json.dumps(
                {
                    "mode": mode,
                    "method": item.method,
                    "endpoint": item.endpoint,
                    "parameter": item.parameter,
                    "payload": payload,
                },
                ensure_ascii=False,
            ),
            response_snapshot="",
            status="failed",
            error=error,
        )
