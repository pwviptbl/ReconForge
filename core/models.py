"""
Modelos de dados padronizados para o VarreduraIA.

Este módulo define estruturas de dados usando dataclasses para garantir
a consistência das informações trocadas entre os plugins e o orquestrador.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any

@dataclass
class Host:
    """Representa um host descoberto."""
    ip: str
    hostname: Optional[str] = None
    os: Optional[str] = None
    mac_address: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os": self.os,
            "mac_address": self.mac_address,
        }

@dataclass
class Port:
    """Representa uma porta de rede em um host."""
    port_number: int
    protocol: str = 'tcp'
    state: str = 'open'

    def to_dict(self) -> Dict[str, Any]:
        return {
            "port_number": self.port_number,
            "protocol": self.protocol,
            "state": self.state,
        }

@dataclass
class Service:
    """Representa um serviço rodando em uma porta."""
    host: Host
    port: Port
    service_name: str
    version: Optional[str] = None
    banner: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "host_ip": self.host.ip,
            "port": self.port.port_number,
            "protocol": self.port.protocol,
            "service_name": self.service_name,
            "version": self.version,
            "banner": self.banner,
        }

@dataclass
class Technology:
    """Representa uma tecnologia detectada em um alvo."""
    name: str
    version: Optional[str] = None
    category: Optional[str] = None
    confidence: int = 100  # Confiança em %

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "category": self.category,
            "confidence": self.confidence,
        }

@dataclass
class Vulnerability:
    """Representa uma vulnerabilidade encontrada."""
    name: str
    description: str
    severity: str  # e.g., 'critical', 'high', 'medium', 'low', 'info'
    cve: Optional[str] = None
    cvss_score: Optional[float] = None
    host: Optional[Host] = None
    port: Optional[Port] = None
    plugin_source: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "cve": self.cve,
            "cvss_score": self.cvss_score,
            "host": self.host.ip if self.host else None,
            "port": self.port.port_number if self.port else None,
            "plugin_source": self.plugin_source,
        }
