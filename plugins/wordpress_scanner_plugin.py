"""
Plugin de Scanner WordPress (wpscan condicional)

Só dispara o `wpscan` quando o alvo é identificado como WordPress — seja
por detecção prévia (WhatWeb/TechnologyDetector no contexto) ou por uma
verificação HTTP leve própria (wp-content, wp-login.php, /wp-json, meta
generator). Isso evita rodar o wpscan em alvos que não são WordPress,
mantendo a filosofia de não gerar ruído desnecessário.

Segue o padrão de integração de subprocess já usado por nmap/whatweb/nuclei.
Como declara requirements=["wpscan"], o PluginManager só o carrega quando o
binário está instalado (ver scripts/system_update.sh).
"""

import json
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

from core.models import Vulnerability
from core.plugin_base import PluginResult, VulnerabilityPlugin
from utils.http_session import create_requests_session
from utils.logger import get_logger

_WP_MARKERS = ("wp-content", "wp-includes", "/wp-json", "wp-login.php")


class WordPressScannerPlugin(VulnerabilityPlugin):
    """Scanner condicional de WordPress baseado em wpscan."""

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        super().__init__(config)
        self.config = config
        self.logger = get_logger(self.__class__.__name__)
        self.requirements = ["wpscan"]
        self.timeout = self.config.get("timeout", 600)
        self.verify_ssl = self.config.get("verify_ssl", True)
        # enumerate: vp=vulnerable plugins, vt=vulnerable themes, u=users
        self.enumerate = self.config.get("enumerate", "vp,vt,u")

    def get_info(self) -> Dict[str, Any]:
        info = super().get_info()
        info["category"] = "vulnerability"
        return info

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()
        actual_target = context.get("original_target", target)

        if not actual_target.startswith(("http://", "https://")):
            actual_target = f"https://{actual_target}"

        if not self._is_wordpress(actual_target, context):
            self.logger.info(f"{self.name}: alvo não identificado como WordPress — pulando")
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={"vulnerabilities": [], "is_wordpress": False},
                summary=f"{self.name}: alvo não é WordPress; wpscan não executado.",
            )

        self.logger.info(f"🚀 WordPress detectado em {actual_target} — executando wpscan")
        wpscan_data, command = self._run_wpscan(actual_target)
        vulns = self._parse_wpscan(wpscan_data, actual_target)

        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=time.time() - start_time,
            data={
                "vulnerabilities": [v.to_dict() for v in vulns],
                "is_wordpress": True,
                "command": [command],
            },
            summary=f"{self.name}: {len(vulns)} achado(s) do wpscan.",
        )

    # ------------------------------------------------------------------ detecção
    def _is_wordpress(self, url: str, context: Dict[str, Any]) -> bool:
        if self.config.get("force", False):
            return True

        # 1. Sinais de detecção prévia no contexto
        discoveries = context.get("discoveries", {})
        techs = discoveries.get("technologies", []) or []
        for tech in techs:
            name = tech if isinstance(tech, str) else (tech.get("name", "") if isinstance(tech, dict) else "")
            if "wordpress" in str(name).lower():
                return True

        plugin_results = context.get("plugin_results", {}) or {}
        for pname in ("WhatWebScannerPlugin", "TechnologyDetectorPlugin"):
            blob = json.dumps(plugin_results.get(pname, {}), default=str).lower()
            if "wordpress" in blob:
                return True

        # 2. Verificação HTTP leve própria
        return self._http_wordpress_check(url, context)

    def _http_wordpress_check(self, url: str, context: Dict[str, Any]) -> bool:
        session = create_requests_session(
            plugin_config=self.config,
            session_file=context.get("auth_session_file"),
        )
        session.verify = self.verify_ssl
        try:
            resp = session.get(url, timeout=self.config.get("http_timeout", 10))
            body = (resp.text or "").lower()
            if any(marker in body for marker in _WP_MARKERS):
                return True
            if "wordpress" in resp.headers.get("X-Powered-By", "").lower():
                return True

            base = f"{urlparse(url).scheme}://{urlparse(url).netloc}"
            login = session.get(f"{base}/wp-login.php", timeout=self.config.get("http_timeout", 10))
            if login.status_code == 200 and "user_login" in (login.text or "").lower():
                return True
        except Exception as e:
            self.logger.debug(f"Checagem HTTP de WordPress falhou: {e}")
        finally:
            session.close()
        return False

    # ------------------------------------------------------------------ wpscan
    def _run_wpscan(self, url: str) -> Tuple[Dict[str, Any], str]:
        wpscan_cmd = shutil.which("wpscan") or "wpscan"
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tf:
            output_file = tf.name

        cmd = [
            wpscan_cmd,
            "--url", url,
            "--format", "json",
            "--output", output_file,
            "--no-banner",
            "--random-user-agent",
            "--enumerate", self.enumerate,
        ]
        if not self.verify_ssl:
            cmd += ["--disable-tls-checks"]
        api_token = self.config.get("api_token")
        if api_token:
            cmd += ["--api-token", str(api_token)]

        executed_command = " ".join(cmd)
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout)
        except subprocess.TimeoutExpired:
            self.logger.warning(f"wpscan timeout em {url} após {self.timeout}s")
        except Exception as e:
            self.logger.warning(f"Falha ao executar wpscan: {e}")

        data: Dict[str, Any] = {}
        try:
            content = Path(output_file).read_text(encoding="utf-8").strip()
            if content:
                data = json.loads(content)
        except Exception as e:
            self.logger.debug(f"Falha ao ler saída do wpscan: {e}")
        finally:
            Path(output_file).unlink(missing_ok=True)
        return data, executed_command

    def _parse_wpscan(self, data: Dict[str, Any], url: str) -> List[Vulnerability]:
        vulns: List[Vulnerability] = []
        if not isinstance(data, dict):
            return vulns

        def _add(name: str, severity: str, description: str, evidence: str, ref: str = ""):
            vulns.append(
                Vulnerability(
                    name=name, severity=severity, description=description,
                    url=url, evidence=evidence, cve="", reference=ref or None,
                    plugin_source=self.name,
                )
            )

        # Versão do core + vulnerabilidades conhecidas
        version = data.get("version") or {}
        if isinstance(version, dict) and version.get("number"):
            core_vulns = version.get("vulnerabilities", []) or []
            _add(
                "WordPress — Versão Detectada",
                "High" if core_vulns else "Info",
                f"WordPress core versão {version.get('number')} detectado"
                + (f" com {len(core_vulns)} vulnerabilidade(s) conhecida(s)." if core_vulns else "."),
                f"Versão: {version.get('number')}\nStatus: {version.get('status', 'n/a')}",
            )
            for cv in core_vulns:
                self._add_known_vuln(vulns, url, "WordPress core", cv)

        # Tema principal
        main_theme = data.get("main_theme") or {}
        if isinstance(main_theme, dict) and main_theme.get("slug"):
            for tv in main_theme.get("vulnerabilities", []) or []:
                self._add_known_vuln(vulns, url, f"Tema {main_theme.get('slug')}", tv)

        # Plugins enumerados
        plugins = data.get("plugins") or {}
        if isinstance(plugins, dict):
            for slug, pdata in plugins.items():
                if not isinstance(pdata, dict):
                    continue
                for pv in pdata.get("vulnerabilities", []) or []:
                    self._add_known_vuln(vulns, url, f"Plugin {slug}", pv)

        # Usuários enumerados (exposição de superfície de brute-force)
        users = data.get("users") or {}
        if isinstance(users, dict) and users:
            _add(
                "WordPress — Usuários Enumeráveis",
                "Medium",
                f"{len(users)} usuário(s) enumerável(is) via wpscan.",
                "Usuários: " + ", ".join(list(users.keys())[:20]),
            )

        return vulns

    def _add_known_vuln(self, vulns: List[Vulnerability], url: str, where: str, cv: Dict[str, Any]):
        if not isinstance(cv, dict):
            return
        title = cv.get("title", "vulnerabilidade conhecida")
        refs = cv.get("references", {}) or {}
        cve_list = refs.get("cve", []) or []
        cve = f"CVE-{cve_list[0]}" if cve_list else ""
        url_refs = refs.get("url", []) or []
        vulns.append(
            Vulnerability(
                name=f"WordPress — {where}: {title}",
                severity="High",
                description=f"{where} vulnerável: {title}",
                url=url,
                evidence=f"Fonte: wpscan\n{where}\n{title}",
                cve=cve,
                reference=url_refs[0] if url_refs else None,
                plugin_source=self.name,
            )
        )
