"""
Plugin Katana Crawler
Uses `katana` (ProjectDiscovery) for fast crawling and endpoint discovery.

This can be a lighter alternative to headless browser crawling for quickly
collecting URLs to feed into ReconForge vulnerability plugins.
"""

from __future__ import annotations

import json
import re
import subprocess
import time
from pathlib import Path
from typing import Any, Dict, List
from urllib.parse import urljoin, urlparse
import shutil

import requests

from core.plugin_base import WebPlugin, PluginResult
from utils.http_session import create_requests_session, resolve_use_tor
from utils.proxy_env import build_proxy_env


class KatanaCrawlerPlugin(WebPlugin):
    """Crawl URLs using `katana` and return discovered endpoints."""

    def __init__(self):
        super().__init__()
        self.description = "Crawler rapido via katana (ProjectDiscovery) para descobrir endpoints"
        self.version = "1.0.0"
        self.category = "web"
        self.supported_targets = ["url", "domain"]
        self.requirements = []  # Possui fallback nativo em Python

    def validate_target(self, target: str) -> bool:
        if not target:
            return False
        if target.startswith(("http://", "https://")):
            parsed = urlparse(target)
            return bool(parsed.scheme and parsed.netloc)
        return "." in target

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()

        try:
            actual_target = context.get("original_target", target)
            seeds = self._build_seed_urls(actual_target, context)
            if not seeds:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="Nenhuma URL semente encontrada para o crawler",
                )

            katana_bin = self._find_katana_bin()
            if not katana_bin:
                # Fallback nativo: crawler leve em Python usando requests + regex
                return self._native_crawl_fallback(seeds, context, start_time)

            depth = int(self.config.get("depth", 2))
            timeout = int(self.config.get("timeout", 180))
            max_urls = int(self.config.get("max_urls", 2000))
            # Note: different katana versions may expose redirect flags differently.
            # Keep defaults conservative to maximize compatibility.

            # Katana can accept a list file in newer versions; use per-seed execution
            # to keep compatibility across installs.
            env = build_proxy_env(use_tor=resolve_use_tor(self.config))
            
            # Determinar o dominio base do alvo para filtrar dominios externos
            target_host = urlparse(seeds[0]).hostname.lower()

            ignored_extensions = {
                ".jpg", ".jpeg", ".png", ".gif", ".ico", ".svg", ".webp",
                ".css", ".scss", ".less", ".js",
                ".woff", ".woff2", ".ttf", ".eot", ".otf",
                ".mp4", ".webm", ".avi", ".mp3", ".wav",
                ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
                ".zip", ".tar", ".gz", ".7z", ".rar"
            }

            endpoints: List[str] = []
            seen = set()
            raw_json: List[Dict[str, Any]] = []
            commands: List[str] = []

            for seed in seeds:
                cmd = [
                    katana_bin,
                    "-u",
                    seed,
                    "-silent",
                    "-json",
                    "-d",
                    str(depth),
                ]
                commands.append(" ".join(cmd))

                # Run and parse JSONL output.
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    env=env,
                    timeout=timeout,
                )

                if result.returncode != 0:
                    # Continue crawling other seeds but keep the error for visibility.
                    raw_json.append(
                        {
                            "seed": seed,
                            "error": (result.stderr or "").strip() or "katana error",
                        }
                    )
                    continue

                for line in (result.stdout or "").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if isinstance(entry, dict):
                        raw_json.append(entry)
                        url = entry.get("url") or entry.get("request") or entry.get("endpoint")
                        if isinstance(url, str) and url.startswith(("http://", "https://")):
                            if url in seen:
                                continue
                            
                            parsed = urlparse(url)
                            host = (parsed.hostname or parsed.netloc or "").lower()
                            
                            # Filtrar dominios externos
                            if target_host and host != target_host and not host.endswith("." + target_host):
                                continue
                            
                            # Filtrar extensoes estaticas
                            path = parsed.path.lower()
                            if any(path.endswith(ext) for ext in ignored_extensions):
                                continue

                            seen.add(url)
                            endpoints.append(url)
                            if len(endpoints) >= max_urls:
                                break
                if len(endpoints) >= max_urls:
                    break

            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={
                    "seeds": seeds,
                    "endpoints": endpoints,
                    "endpoints_count": len(endpoints),
                    "raw": raw_json[:200],  # keep report size bounded
                    "command": commands
                },
                summary=f"katana descobriu {len(endpoints)} endpoints (depth={depth}).",
            )

        except subprocess.TimeoutExpired:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error="katana timeout",
            )
        except Exception as e:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=str(e),
            )

    def _build_seed_urls(self, target: str, context: Dict[str, Any]) -> List[str]:
        if target.startswith(("http://", "https://")):
            return [target]

        host = target.split("/", 1)[0].split(":", 1)[0]
        open_ports = context.get("discoveries", {}).get("open_ports", [])
        seeds: List[str] = []

        if 80 in open_ports:
            seeds.append(f"http://{host}")
        if 443 in open_ports:
            seeds.append(f"https://{host}")

        # Common web alt ports.
        for port in [8080, 8000, 8443, 3000, 5000, 5001, 9000]:
            if port in open_ports:
                scheme = "https" if port in [8443, 9443] else "http"
                seeds.append(f"{scheme}://{host}:{port}")

        if not seeds:
            seeds = [f"http://{host}", f"https://{host}"]

        # Keep order + uniqueness.
        out: List[str] = []
        seen = set()
        for s in seeds:
            if s not in seen:
                out.append(s)
                seen.add(s)
        return out

    def _find_katana_bin(self) -> str:
        found = shutil.which("katana")
        if found:
            return found
        fallback = Path.home() / "go" / "bin" / "katana"
        if fallback.is_file():
            return str(fallback)
        return ""

    def _native_crawl_fallback(
        self,
        seeds: List[str],
        context: Dict[str, Any],
        start_time: float,
    ) -> PluginResult:
        """Fallback leve em Python quando katana não está disponível."""
        session = create_requests_session(plugin_config=self.config)
        session.headers.update({"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ReconForge/3.0"})
        max_urls = int(self.config.get("max_urls", 200))
        depth = int(self.config.get("depth", 2))
        
        target_host = urlparse(seeds[0]).hostname.lower()
        endpoints = []
        visited = set()
        queue = [(seed, 0) for seed in seeds]

        link_regex = re.compile(r'(?:href|src|action)=["\']([^"\']+)["\']', re.IGNORECASE)

        while queue and len(endpoints) < max_urls:
            current_url, cur_depth = queue.pop(0)
            if current_url in visited or cur_depth > depth:
                continue
            visited.add(current_url)
            endpoints.append(current_url)

            try:
                resp = session.get(current_url, timeout=5, verify=False, allow_redirects=True)
                if "text/html" not in resp.headers.get("content-type", "").lower():
                    continue

                for match in link_regex.finditer(resp.text):
                    link = match.group(1).strip()
                    if link.startswith(("#", "javascript:", "mailto:", "tel:")):
                        continue
                    full_link = urljoin(current_url, link)
                    parsed = urlparse(full_link)
                    host = (parsed.hostname or "").lower()

                    if target_host and host == target_host and full_link not in visited:
                        queue.append((full_link, cur_depth + 1))
            except Exception:
                continue

        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=time.time() - start_time,
            data={
                "seeds": seeds,
                "endpoints": endpoints,
                "endpoints_count": len(endpoints),
                "raw": [],
                "engine": "native_fallback",
            },
            summary=f"Crawler nativo descobriu {len(endpoints)} endpoints (modo fallback).",
        )
