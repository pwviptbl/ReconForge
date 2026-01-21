"""
Plugin para avaliacao de politicas SSH.
Analisa algoritmos anunciados e identifica opcoes fracas.
"""

import subprocess
import time
import xml.etree.ElementTree as ET
from typing import Dict, Any, List, Tuple
from pathlib import Path

import sys
sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult


class SSHPolicyCheck(NetworkPlugin):
    """Verifica algoritmos SSH e sinaliza politicas fracas."""

    def __init__(self):
        super().__init__()
        self.name = "SSHPolicyCheck"
        self.description = "Avalia algoritmos SSH (KEX, cifragem, MAC e chaves) e detecta opcoes fracas."
        self.version = "1.0.0"
        self.requirements = ["nmap"]
        self.supported_targets = ["ip", "domain"]
        self.config = {
            "nmap_timeout": 180,
            "timing": "T3"
        }

        self.weak_algorithms = {
            "kex": {
                "diffie-hellman-group1-sha1",
                "diffie-hellman-group14-sha1",
                "diffie-hellman-group-exchange-sha1"
            },
            "ciphers": {
                "3des-cbc",
                "aes128-cbc",
                "aes192-cbc",
                "aes256-cbc",
                "arcfour",
                "arcfour128",
                "arcfour256",
                "blowfish-cbc",
                "cast128-cbc",
                "des-cbc",
                "rijndael-cbc@lysator.liu.se"
            },
            "macs": {
                "hmac-md5",
                "hmac-md5-96",
                "hmac-sha1",
                "hmac-sha1-96",
                "umac-64@openssh.com"
            },
            "host_keys": {
                "ssh-dss",
                "ssh-rsa"
            }
        }

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()

        ssh_ports = self._detect_ssh_ports(context)
        if not ssh_ports:
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                summary="Nenhuma porta SSH identificada para analise."
            )

        results = []
        recommendations = []

        for port in ssh_ports:
            data = self._run_nmap(target, port)
            if not data:
                continue

            algorithms, service_info = data
            weak = self._find_weak_algorithms(algorithms)
            severity = self._severity_from_weak(weak)
            if any(weak.values()):
                recs = self._build_recommendations(port, weak)
                recommendations.extend(recs)

            results.append({
                "port": port,
                "service": service_info.get("service"),
                "product": service_info.get("product"),
                "version": service_info.get("version"),
                "algorithms": algorithms,
                "weak_algorithms": weak,
                "severity": severity
            })

        summary = self._build_summary(results)
        execution_time = time.time() - start_time

        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=execution_time,
            data={
                "ssh_ports": ssh_ports,
                "results": results,
                "summary": summary,
                "recommendations": recommendations
            },
            summary=f"Portas analisadas: {summary.get('ports_checked', 0)}."
        )

    def _detect_ssh_ports(self, context: Dict[str, Any]) -> List[int]:
        discoveries = context.get("discoveries", {})
        services = discoveries.get("services", [])
        open_ports = discoveries.get("open_ports", [])

        ssh_ports = set()
        for service in services:
            if not isinstance(service, dict):
                continue
            name = str(service.get("service", "")).lower()
            product = str(service.get("product", "")).lower()
            if name == "ssh" or "ssh" in product:
                port = service.get("port")
                if port:
                    ssh_ports.add(int(port))

        if not ssh_ports and 22 in open_ports:
            ssh_ports.add(22)

        if not ssh_ports:
            ssh_ports.add(22)

        return sorted(ssh_ports)

    def _run_nmap(self, target: str, port: int) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
        timing = self.config.get("timing", "T3")
        timeout = int(self.config.get("nmap_timeout", 180))
        cmd = [
            "nmap",
            f"-{timing}",
            "-sV",
            "-p",
            str(port),
            "--script",
            "ssh2-enum-algos",
            "-oX",
            "-",
            target
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )
        except subprocess.TimeoutExpired:
            return None

        if not result.stdout.strip():
            return None

        return self._parse_nmap_output(result.stdout, port)

    def _parse_nmap_output(self, xml_output: str, port: int) -> Tuple[Dict[str, List[str]], Dict[str, str]]:
        algorithms = {
            "kex": [],
            "host_keys": [],
            "ciphers": [],
            "macs": [],
            "compression": []
        }
        service_info = {}

        try:
            root = ET.fromstring(xml_output)
        except ET.ParseError:
            return algorithms, service_info

        for host in root.findall("host"):
            for port_el in host.findall(".//port"):
                if port_el.get("portid") != str(port):
                    continue
                service = port_el.find("service")
                if service is not None:
                    service_info = {
                        "service": service.get("name"),
                        "product": service.get("product"),
                        "version": service.get("version")
                    }
                script = port_el.find("./script[@id='ssh2-enum-algos']")
                if script is None:
                    continue
                tables = script.findall("table")
                if tables:
                    self._parse_tables(tables, algorithms)
                else:
                    self._parse_output_text(script.get("output", ""), algorithms)

        return algorithms, service_info

    def _parse_tables(self, tables: List[ET.Element], algorithms: Dict[str, List[str]]):
        mapping = {
            "kex_algorithms": "kex",
            "server_host_key_algorithms": "host_keys",
            "encryption_algorithms": "ciphers",
            "mac_algorithms": "macs",
            "compression_algorithms": "compression"
        }
        for table in tables:
            key = table.get("key")
            target = mapping.get(key)
            if not target:
                continue
            for elem in table.findall("elem"):
                value = (elem.text or "").strip()
                if value:
                    algorithms[target].append(value)

    def _parse_output_text(self, output: str, algorithms: Dict[str, List[str]]):
        current = None
        mapping = {
            "kex_algorithms": "kex",
            "server_host_key_algorithms": "host_keys",
            "encryption_algorithms": "ciphers",
            "mac_algorithms": "macs",
            "compression_algorithms": "compression"
        }
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.endswith(":"):
                key = line.rstrip(":").lower().replace(" ", "_")
                current = mapping.get(key)
                continue
            if current and line.startswith("|"):
                algo = line.strip("| ").strip()
                if algo:
                    algorithms[current].append(algo)

    def _find_weak_algorithms(self, algorithms: Dict[str, List[str]]) -> Dict[str, List[str]]:
        weak = {
            "kex": [],
            "host_keys": [],
            "ciphers": [],
            "macs": []
        }
        for key in weak.keys():
            weak[key] = [algo for algo in algorithms.get(key, []) if algo in self.weak_algorithms.get(key, set())]
        return weak

    def _severity_from_weak(self, weak: Dict[str, List[str]]) -> str:
        if weak.get("host_keys") or weak.get("ciphers"):
            return "High"
        if weak.get("kex") or weak.get("macs"):
            return "Medium"
        return "Info"

    def _build_recommendations(self, port: int, weak: Dict[str, List[str]]) -> List[str]:
        recs = []
        for key, items in weak.items():
            if items:
                recs.append(
                    f"Porta {port}: desabilitar {key} fracos ({', '.join(items)})"
                )
        return recs

    def _build_summary(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        ports_checked = len(results)
        ports_with_weak = 0
        counts = {
            "kex": 0,
            "host_keys": 0,
            "ciphers": 0,
            "macs": 0
        }
        for entry in results:
            weak = entry.get("weak_algorithms", {})
            if any(weak.values()):
                ports_with_weak += 1
            for key in counts.keys():
                counts[key] += len(weak.get(key, []))
        return {
            "ports_checked": ports_checked,
            "ports_with_weak": ports_with_weak,
            "weak_counts": counts
        }
