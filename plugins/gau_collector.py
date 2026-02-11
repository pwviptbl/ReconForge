"""
Plugin Gau Collector
Collects historical URLs from public sources (Wayback, CommonCrawl, etc.)
using `gau` and feeds them into ReconForge as discovered endpoints.
"""

from __future__ import annotations

import subprocess
import time
from typing import Any, Dict, List
from urllib.parse import urlparse
from pathlib import Path
import shutil

from core.plugin_base import WebPlugin, PluginResult
from utils.http_session import resolve_use_tor
from utils.proxy_env import build_proxy_env


class GauCollectorPlugin(WebPlugin):
    """Collect URLs for a domain using `gau`."""

    def __init__(self):
        super().__init__()
        self.description = "Coleta URLs historicas (Wayback/CommonCrawl/etc.) via gau"
        self.version = "1.0.0"
        self.category = "web"
        self.supported_targets = ["domain", "url"]
        self.requirements = ["gau"]

    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        if target.startswith(("http://", "https://")):
            host = urlparse(target).hostname
            return bool(host and "." in host)
        return "." in target

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()

        try:
            gau_bin = self._find_gau_bin()
            if not gau_bin:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="gau nao encontrado no PATH nem em ~/go/bin/gau",
                )

            actual_target = context.get("original_target", target)
            domain = self._extract_domain(actual_target)
            if not domain:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="Nao foi possivel extrair dominio para executar gau",
                )

            timeout = int(self.config.get("timeout", 120))
            include_subs = bool(self.config.get("include_subdomains", True))
            max_urls = int(self.config.get("max_urls", 2000))

            cmd: List[str] = [gau_bin]
            if include_subs:
                cmd.append("--subs")
            cmd.append(domain)

            env = build_proxy_env(use_tor=resolve_use_tor(self.config))
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                env=env,
                timeout=timeout,
            )

            if result.returncode != 0:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={"stdout": result.stdout, "stderr": result.stderr},
                    error=result.stderr.strip() or "Falha ao executar gau",
                )

            endpoints = []
            seen = set()
            for line in (result.stdout or "").splitlines():
                url = line.strip()
                if not url or url in seen:
                    continue
                if not url.startswith(("http://", "https://")):
                    continue
                host = urlparse(url).hostname or ""
                if domain not in host:
                    continue
                seen.add(url)
                endpoints.append(url)
                if len(endpoints) >= max_urls:
                    break

            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={
                    "domain": domain,
                    "endpoints": endpoints,
                    "endpoints_count": len(endpoints),
                },
                summary=f"gau coletou {len(endpoints)} URLs para {domain}.",
            )

        except subprocess.TimeoutExpired:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error="gau timeout",
            )
        except Exception as e:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=str(e),
            )

    def _extract_domain(self, target: str) -> str:
        if not target:
            return ""
        if target.startswith(("http://", "https://")):
            host = urlparse(target).hostname
            return host or ""
        # target might include port/path
        host = target.split("/", 1)[0].split(":", 1)[0]
        return host

    def _find_gau_bin(self) -> str:
        found = shutil.which("gau")
        if found:
            return found
        fallback = Path.home() / "go" / "bin" / "gau"
        if fallback.is_file():
            return str(fallback)
        return ""
