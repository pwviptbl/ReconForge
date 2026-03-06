#!/usr/bin/env python3
"""
API HTTP simples para submissão de scans e consulta de runs — Fase 4.

Mantém dependência zero de framework web para facilitar execução no ambiente
atual. A migração para FastAPI fica natural numa etapa posterior.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict
from urllib.parse import parse_qs, urlparse


PROJECT_ROOT = Path(__file__).resolve().parent.parent
os.chdir(PROJECT_ROOT)
sys.path.insert(0, str(PROJECT_ROOT))

from core.config import get_config
from core.plugin_manager import PluginManager
from core.storage import Storage
from core.workflow_orchestrator import run_pipeline
from utils.logger import setup_logger
from utils.runtime_health import collect_runtime_health
from utils.runtime_profiles import resolve_profile_plugins
from utils.web_map import build_web_map_payload


def _json_response(handler: BaseHTTPRequestHandler, payload: Dict[str, Any], status: int = 200) -> None:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    handler.send_response(status)
    handler.send_header("Content-Type", "application/json; charset=utf-8")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class ReconForgeAPIHandler(BaseHTTPRequestHandler):
    server_version = "ReconForgeAPI/0.1"

    def do_GET(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/health":
            health = collect_runtime_health(self.server.plugin_manager)
            return _json_response(self, {"status": "ok", **health})

        if parsed.path.startswith("/run/"):
            return self._handle_run_get(parsed)

        _json_response(self, {"error": "endpoint não encontrado"}, status=404)

    def do_POST(self):  # noqa: N802
        parsed = urlparse(self.path)
        if parsed.path == "/scan":
            return self._handle_scan_post()

        _json_response(self, {"error": "endpoint não encontrado"}, status=404)

    def log_message(self, fmt: str, *args):  # noqa: A003
        self.server.logger.info("%s - %s", self.address_string(), fmt % args)

    @property
    def storage(self) -> Storage:
        return self.server.storage

    def _read_json(self) -> Dict[str, Any]:
        length = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(length) if length else b"{}"
        return json.loads(raw.decode("utf-8") or "{}")

    def _handle_scan_post(self):
        try:
            payload = self._read_json()
        except json.JSONDecodeError:
            return _json_response(self, {"error": "JSON inválido"}, status=400)

        target = str(payload.get("target", "")).strip()
        if not target:
            return _json_response(self, {"error": "campo 'target' é obrigatório"}, status=400)

        recon_plugins = payload.get("recon_plugins")
        detect_plugins = payload.get("detect_plugins")
        profile_name = payload.get("profile")
        if profile_name:
            try:
                resolved = resolve_profile_plugins(
                    str(profile_name),
                    list(self.server.plugin_manager.plugins.keys()),
                )
            except ValueError as exc:
                return _json_response(self, {"error": str(exc)}, status=400)

            if resolved.get("missing_required"):
                missing = ", ".join(resolved["missing_required"])
                return _json_response(
                    self,
                    {"error": f"perfil '{profile_name}' indisponível: {missing}"},
                    status=400,
                )
            recon_plugins = resolved.get("recon_plugins") or recon_plugins
            detect_plugins = resolved.get("detect_plugins") or detect_plugins

        state = run_pipeline(
            target=target,
            verbose=bool(payload.get("verbose", False)),
            quiet=bool(payload.get("quiet", True)),
            recon_plugins=recon_plugins,
            detect_plugins=detect_plugins,
            max_exploit_attempts=int(payload.get("max_exploit_attempts", 5)),
            exploit_categories=payload.get("exploit_categories"),
        )

        return _json_response(
            self,
            {
                "run_id": state.run_id,
                "target": state.target,
                "summary": state.summary(),
                "report_path": state.report_path,
                "web_map": build_web_map_payload(state.discoveries),
            },
            status=HTTPStatus.CREATED,
        )

    def _handle_run_get(self, parsed):
        parts = [part for part in parsed.path.split("/") if part]
        if len(parts) < 2:
            return _json_response(self, {"error": "run_id ausente"}, status=400)

        try:
            run_id = int(parts[1])
        except ValueError:
            return _json_response(self, {"error": "run_id inválido"}, status=400)

        if len(parts) == 2:
            summary = self.storage.get_run_summary(run_id)
            if not summary:
                return _json_response(self, {"error": "run não encontrado"}, status=404)
            return _json_response(self, summary)

        if len(parts) == 3 and parts[2] == "queue":
            items = [item.to_dict() for item in self.storage.load_queue_items(run_id)]
            return _json_response(self, {"run_id": run_id, "queue_items": items})

        if len(parts) == 3 and parts[2] == "evidence":
            evidences = [evidence.to_dict() for evidence in self.storage.load_evidences(run_id)]
            return _json_response(self, {"run_id": run_id, "evidences": evidences})

        if len(parts) == 3 and parts[2] == "report":
            loaded = self.storage.load_run_by_id(run_id)
            if not loaded:
                return _json_response(self, {"error": "run não encontrado"}, status=404)

            _, context, _, target = loaded
            report_path = context.get("report_path", "")
            query = parse_qs(parsed.query)
            include_content = query.get("content", ["0"])[0] == "1"
            payload = {
                "run_id": run_id,
                "target": target,
                "report_path": report_path,
            }
            if include_content and report_path and Path(report_path).exists():
                payload["content"] = Path(report_path).read_text(encoding="utf-8")
            return _json_response(self, payload)

        if len(parts) == 3 and parts[2] == "webmap":
            loaded = self.storage.load_run_by_id(run_id)
            if not loaded:
                return _json_response(self, {"error": "run não encontrado"}, status=404)

            _, context, _, target = loaded
            return _json_response(
                self,
                {
                    "run_id": run_id,
                    "target": target,
                    "web_map": build_web_map_payload(context.get("discoveries", {})),
                },
            )

        return _json_response(self, {"error": "subrota não suportada"}, status=404)


def main() -> int:
    parser = argparse.ArgumentParser(description="ReconForge HTTP API")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--data-dir", default=get_config("output.data_dir", "data"))
    args = parser.parse_args()

    logger = setup_logger("ReconForgeAPI", verbose=True)
    storage = Storage(Path(args.data_dir) / "reconforge.db")

    server = ThreadingHTTPServer((args.host, args.port), ReconForgeAPIHandler)
    server.logger = logger
    server.storage = storage
    server.plugin_manager = PluginManager()

    logger.info(f"API iniciada em http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Encerrando API...")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
