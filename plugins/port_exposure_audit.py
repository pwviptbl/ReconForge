"""
Plugin de auditoria de exposicao de portas.
Identifica servicos expostos considerados arriscados.
"""

import time
from typing import Dict, Any, List
from pathlib import Path
import sys

sys.path.append(str(Path(__file__).parent.parent))

from core.plugin_base import NetworkPlugin, PluginResult


class PortExposureAudit(NetworkPlugin):
    """Avalia exposicao de portas e servicos sensiveis."""

    def __init__(self):
        super().__init__()
        self.name = "PortExposureAudit"
        self.description = "Audita exposicao de portas e servicos sensiveis."
        self.version = "1.0.0"
        self.supported_targets = ["ip", "domain"]
        self.config = {
            "allow_ports": [],
            "allow_services": []
        }

        self.risky_ports = {
            21: ("ftp", "High"),
            22: ("ssh", "Medium"),
            23: ("telnet", "Critical"),
            25: ("smtp", "Medium"),
            53: ("dns", "Low"),
            110: ("pop3", "Medium"),
            111: ("rpcbind", "Medium"),
            135: ("msrpc", "High"),
            139: ("netbios-ssn", "High"),
            143: ("imap", "Medium"),
            161: ("snmp", "High"),
            389: ("ldap", "Medium"),
            445: ("microsoft-ds", "High"),
            512: ("exec", "High"),
            513: ("login", "High"),
            514: ("shell", "High"),
            873: ("rsync", "Medium"),
            993: ("imaps", "Medium"),
            995: ("pop3s", "Medium"),
            1433: ("mssql", "High"),
            1521: ("oracle", "High"),
            2049: ("nfs", "High"),
            3306: ("mysql", "High"),
            3389: ("rdp", "High"),
            5432: ("postgresql", "High"),
            5900: ("vnc", "High"),
            5985: ("winrm", "Medium"),
            5986: ("winrm", "Medium"),
            6379: ("redis", "Critical"),
            8080: ("http-alt", "Low"),
            8081: ("http-alt", "Low"),
            9200: ("elasticsearch", "High"),
            9300: ("elasticsearch", "High"),
            27017: ("mongodb", "High"),
            2375: ("docker", "Critical"),
            2376: ("docker", "High"),
            11211: ("memcached", "High"),
            5000: ("registry", "Medium"),
            5601: ("kibana", "Medium"),
            15672: ("rabbitmq", "Medium")
        }

        self.risky_services = {
            "ftp",
            "telnet",
            "netbios-ssn",
            "microsoft-ds",
            "smb",
            "rdp",
            "mysql",
            "postgresql",
            "redis",
            "mongodb",
            "mssql",
            "nfs",
            "memcached",
            "elasticsearch",
            "docker",
            "vnc",
            "snmp"
        }

    def execute(self, target: str, context: Dict[str, Any], **kwargs) -> PluginResult:
        start_time = time.time()

        discoveries = context.get("discoveries", {})
        open_ports = discoveries.get("open_ports", [])
        services = discoveries.get("services", [])

        if not open_ports:
            return PluginResult(
                success=True,
                plugin_name=self.name,
                execution_time=time.time() - start_time,
                data={},
                summary="Nenhuma porta aberta encontrada para auditar."
            )

        service_by_port = {}
        for service in services:
            if not isinstance(service, dict):
                continue
            port = service.get("port")
            if port is None:
                continue
            service_by_port[int(port)] = service

        allow_ports = set(self.config.get("allow_ports", []))
        allow_services = set(s.lower() for s in self.config.get("allow_services", []))

        exposures = []
        for port in sorted(set(open_ports)):
            if port in allow_ports:
                continue
            service = service_by_port.get(port, {})
            service_name = str(service.get("service", "")).lower()
            product = str(service.get("product", "")).strip()
            version = str(service.get("version", "")).strip()

            if service_name in allow_services:
                continue

            risk = self.risky_ports.get(port)
            if risk:
                expected_service, severity = risk
                exposures.append({
                    "port": port,
                    "service": service_name or expected_service,
                    "product": product,
                    "version": version,
                    "severity": severity,
                    "reason": f"Porta sensivel exposta ({expected_service})"
                })
                continue

            if service_name and service_name in self.risky_services:
                exposures.append({
                    "port": port,
                    "service": service_name,
                    "product": product,
                    "version": version,
                    "severity": "Medium",
                    "reason": "Servico sensivel exposto"
                })

        summary = self._build_summary(exposures)

        return PluginResult(
            success=True,
            plugin_name=self.name,
            execution_time=time.time() - start_time,
            data={
                "open_ports": sorted(set(open_ports)),
                "exposures": exposures,
                "summary": summary
            },
            summary=f"Exposicoes detectadas: {summary.get('total', 0)}."
        )

    def _build_summary(self, exposures: List[Dict[str, Any]]) -> Dict[str, Any]:
        counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for item in exposures:
            severity = item.get("severity", "Info")
            counts[severity] = counts.get(severity, 0) + 1
        return {
            "total": len(exposures),
            "by_severity": counts
        }
