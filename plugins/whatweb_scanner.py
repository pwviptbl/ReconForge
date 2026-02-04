"""
Plugin WhatWeb para detecao de tecnologias web
Usa WhatWeb para identificar stacks e frameworks
"""

import json
import subprocess
import tempfile
import time
import shutil
import os
from typing import Dict, Any, List
from urllib.parse import urlparse

import sys
from pathlib import Path
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import WebPlugin, PluginResult
from core.config import get_config


class WhatWebScannerPlugin(WebPlugin):
    """Plugin para detecao de tecnologias usando WhatWeb"""

    def __init__(self):
        super().__init__()
        self.description = "Detecao de tecnologias com WhatWeb"
        self.version = "1.0.0"
        self.requirements = ["whatweb"]
        self.supported_targets = ["url", "domain"]

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        """Executa o WhatWeb"""
        start_time = time.time()

        try:
            urls = self._get_urls_to_try(target, context)
            if not urls:
                return PluginResult(
                    success=False,
                    plugin_name=self.name,
                    execution_time=time.time() - start_time,
                    data={},
                    error="Nenhuma URL valida para executar WhatWeb"
                )

            aggression = get_config('plugins.config.WhatWebScannerPlugin.aggression', 1)
            timeout = get_config('plugins.config.WhatWebScannerPlugin.timeout', 60)

            findings = []
            technologies = []

            for url in urls:
                result = self._run_whatweb(url, aggression, timeout)
                findings.extend(result.get('findings', []))
                for tech in result.get('technologies', []):
                    if tech not in technologies:
                        technologies.append(tech)

            execution_time = time.time() - start_time

            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=execution_time,
                data={
                    'urls_scanned': urls,
                    'technologies': technologies,
                    'findings': findings
                }
            )

        except Exception as e:
            return PluginResult(
                success=False,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                error=str(e)
            )

    def validate_target(self, target: str) -> bool:
        """Valida se o alvo e uma URL ou dominio"""
        if target.startswith(('http://', 'https://')):
            parsed = urlparse(target)
            return parsed.scheme in ['http', 'https'] and bool(parsed.netloc)
        return '.' in target

    def _get_urls_to_try(self, target: str, context: Dict[str, Any]) -> List[str]:
        """Gera URLs candidatas para o WhatWeb"""
        if target.startswith(('http://', 'https://')):
            return [target]

        urls = []
        open_ports = context.get('discoveries', {}).get('open_ports', [])

        if 443 in open_ports:
            urls.append(f"https://{target}")
        if 80 in open_ports or not urls:
            urls.append(f"http://{target}")

        alt_ports = [8080, 8000, 8443, 3000, 5000]
        for port in alt_ports:
            if port in open_ports:
                scheme = 'https' if port in [8443] else 'http'
                urls.append(f"{scheme}://{target}:{port}")

        return urls

    def _run_whatweb(self, url: str, aggression: int, timeout: int) -> Dict[str, Any]:
        """Executa WhatWeb e processa o resultado"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as temp_file:
            output_file = temp_file.name

        whatweb_cmd = shutil.which('whatweb')
        if not whatweb_cmd:
            fallback = "/usr/share/whatweb/whatweb"
            if Path(fallback).is_file() and os.access(fallback, os.X_OK):
                whatweb_cmd = fallback
            else:
                whatweb_cmd = "whatweb"

        cmd = [
            whatweb_cmd,
            '-a', str(aggression),
            '--log-json', output_file,
            url
        ]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        if result.returncode != 0:
            return {
                'findings': [],
                'technologies': [],
                'errors': result.stderr.strip()
            }

        findings = []
        technologies = []

        try:
            with open(output_file, 'r', encoding='utf-8') as f:
                content = f.read().strip()

            parsed_entries = []
            for line in content.splitlines():
                line = line.strip()
                if not line:
                    continue
                try:
                    parsed_entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue

            if not parsed_entries and content:
                try:
                    parsed_entries = [json.loads(content)]
                except json.JSONDecodeError:
                    parsed_entries = []

            for entry in parsed_entries:
                if not isinstance(entry, dict):
                    continue
                findings.append(entry)
                plugins = entry.get('plugins', {})
                if isinstance(plugins, dict):
                    for tech in plugins.keys():
                        if tech not in technologies:
                            technologies.append(tech)

        finally:
            Path(output_file).unlink(missing_ok=True)

        return {
            'findings': findings,
            'technologies': technologies
        }
