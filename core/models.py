"""
Modelos de dados padronizados para o ReconForge.

Este módulo define estruturas de dados usando dataclasses para garantir
a consistência das informações trocadas entre os plugins e o orquestrador.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
import uuid
from datetime import datetime, timezone

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
    host: Optional[str] = None # Mudado para str para simplificar ou manter Host? Manter Host se possível, mas aqui está Optional[Host].
    port: Optional[Port] = None
    url: Optional[str] = None
    evidence: Optional[str] = None
    remediation: Optional[str] = None
    reference: Optional[str] = None
    plugin_source: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "severity": self.severity,
            "cve": self.cve,
            "cvss_score": self.cvss_score,
            "host": self.host.ip if self.host and hasattr(self.host, 'ip') else str(self.host) if self.host else None,
            "port": self.port.port_number if self.port and hasattr(self.port, 'port_number') else str(self.port) if self.port else None,
            "url": self.url,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "reference": self.reference,
            "plugin_source": self.plugin_source,
        }


# ---------------------------------------------------------------------------
# Modelos de Workflow — Fase 1
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id() -> str:
    return str(uuid.uuid4())


# Estágios possíveis de um Finding ao longo do pipeline
FINDING_STAGES = (
    "detected",       # Saiu de um plugin de detecção
    "validated",      # Passou pelo ValidationGate
    "queued",         # Entrou na ExploitQueue
    "exploited",      # Tentativa de exploit rodou
    "false_positive", # Rejeitado pelo ValidationGate
)

# Níveis de prova de uma evidência
PROOF_LEVELS = ("none", "partial", "impact_proven")

# Status de item na queue
QUEUE_STATUS = ("pending", "in_progress", "done", "failed", "skipped")


@dataclass
class Finding:
    """
    Achado bruto gerado por um plugin de detecção.
    Representa um sinal de vulnerabilidade ainda não validado nem explorado.
    """
    category: str                           # "xss", "sqli", "ssrf", "lfi", "idor", "auth", ...
    target: str                             # Host/URL alvo
    endpoint: str                           # Endpoint específico (/search, /login, ...)
    method: str                             # HTTP method (GET, POST, ...)
    parameter: str                          # Parâmetro vulnerável (q, id, url, ...)
    detection_source: str                   # Nome do plugin que gerou o finding
    id: str = field(default_factory=_new_id)
    context: str = "HTML_BODY"              # "HTML_BODY", "ATTRIBUTE", "JS_STRING", "URL", "HEADER"
    candidate_payload: str = ""             # Payload que disparou a detecção
    raw_evidence: str = ""                  # Snippet de resposta que motivou a detecção
    confidence_score: float = 0.5           # 0.0 a 1.0
    externally_exploitable: bool = True
    stage: str = "detected"
    run_id: Optional[int] = None
    created_at: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "category": self.category,
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "context": self.context,
            "candidate_payload": self.candidate_payload,
            "detection_source": self.detection_source,
            "raw_evidence": self.raw_evidence,
            "confidence_score": self.confidence_score,
            "externally_exploitable": self.externally_exploitable,
            "stage": self.stage,
            "run_id": self.run_id,
            "created_at": self.created_at,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Finding":
        return cls(
            id=d.get("id", _new_id()),
            category=d["category"],
            target=d["target"],
            endpoint=d.get("endpoint", ""),
            method=d.get("method", "GET"),
            parameter=d.get("parameter", ""),
            context=d.get("context", "HTML_BODY"),
            candidate_payload=d.get("candidate_payload", ""),
            detection_source=d.get("detection_source", ""),
            raw_evidence=d.get("raw_evidence", ""),
            confidence_score=float(d.get("confidence_score", 0.5)),
            externally_exploitable=bool(d.get("externally_exploitable", True)),
            stage=d.get("stage", "detected"),
            run_id=d.get("run_id"),
            created_at=d.get("created_at", _now_iso()),
        )


@dataclass
class QueueItem:
    """
    Item da fila de exploração gerado a partir de um Finding validado.
    Controla o ciclo de vida da exploração de cada vulnerabilidade identificada.
    """
    finding_id: str
    category: str
    id: str = field(default_factory=_new_id)
    priority: int = 5                       # 1 (crítico) a 5 (info) — menor = maior prioridade
    status: str = "pending"                 # Ver QUEUE_STATUS
    assigned_executor: str = ""             # Pipeline/executor responsável
    run_id: Optional[int] = None
    created_at: str = field(default_factory=_now_iso)
    updated_at: str = field(default_factory=_now_iso)

    # Campos preenchidos a partir do Finding original para evitar
    # consultas adicionais durante a exploração
    target: str = ""
    endpoint: str = ""
    method: str = "GET"
    parameter: str = ""
    context: str = "HTML_BODY"
    candidate_payload: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "finding_id": self.finding_id,
            "category": self.category,
            "priority": self.priority,
            "status": self.status,
            "assigned_executor": self.assigned_executor,
            "run_id": self.run_id,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "target": self.target,
            "endpoint": self.endpoint,
            "method": self.method,
            "parameter": self.parameter,
            "context": self.context,
            "candidate_payload": self.candidate_payload,
        }

    @classmethod
    def from_finding(cls, finding: Finding, priority: int = 5) -> "QueueItem":
        return cls(
            finding_id=finding.id,
            category=finding.category,
            priority=priority,
            run_id=finding.run_id,
            target=finding.target,
            endpoint=finding.endpoint,
            method=finding.method,
            parameter=finding.parameter,
            context=finding.context,
            candidate_payload=finding.candidate_payload,
        )

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "QueueItem":
        return cls(
            id=d.get("id", _new_id()),
            finding_id=d["finding_id"],
            category=d["category"],
            priority=int(d.get("priority", 5)),
            status=d.get("status", "pending"),
            assigned_executor=d.get("assigned_executor", ""),
            run_id=d.get("run_id"),
            created_at=d.get("created_at", _now_iso()),
            updated_at=d.get("updated_at", _now_iso()),
            target=d.get("target", ""),
            endpoint=d.get("endpoint", ""),
            method=d.get("method", "GET"),
            parameter=d.get("parameter", ""),
            context=d.get("context", "HTML_BODY"),
            candidate_payload=d.get("candidate_payload", ""),
        )


@dataclass
class ExploitAttempt:
    """
    Registro de uma tentativa individual de exploração sobre um QueueItem.
    Cada item pode ter múltiplas tentativas com payloads diferentes.
    """
    queue_item_id: str
    attempt_number: int
    payload_used: str
    executor: str
    id: str = field(default_factory=_new_id)
    request_snapshot: str = ""              # Raw HTTP request enviado
    response_snapshot: str = ""             # Raw HTTP response recebido
    status: str = "failed"                  # "failed", "partial", "impact_proven"
    error: Optional[str] = None
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "queue_item_id": self.queue_item_id,
            "attempt_number": self.attempt_number,
            "payload_used": self.payload_used,
            "executor": self.executor,
            "request_snapshot": self.request_snapshot,
            "response_snapshot": self.response_snapshot,
            "status": self.status,
            "error": self.error,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ExploitAttempt":
        return cls(
            id=d.get("id", _new_id()),
            queue_item_id=d["queue_item_id"],
            attempt_number=int(d["attempt_number"]),
            payload_used=d.get("payload_used", ""),
            executor=d.get("executor", ""),
            request_snapshot=d.get("request_snapshot", ""),
            response_snapshot=d.get("response_snapshot", ""),
            status=d.get("status", "failed"),
            error=d.get("error"),
            timestamp=d.get("timestamp", _now_iso()),
        )


@dataclass
class Evidence:
    """
    Evidência coletada após tentativas de exploração de um QueueItem.
    Classifica o nível de prova obtido e referencia os artefatos salvos.
    """
    queue_item_id: str
    attempt_id: str
    proof_level: str = "none"               # Ver PROOF_LEVELS
    artifacts: List[str] = field(default_factory=list)   # Caminhos de arquivos
    impact_summary: str = ""
    id: str = field(default_factory=_new_id)
    timestamp: str = field(default_factory=_now_iso)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "queue_item_id": self.queue_item_id,
            "attempt_id": self.attempt_id,
            "proof_level": self.proof_level,
            "artifacts": self.artifacts,
            "impact_summary": self.impact_summary,
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "Evidence":
        return cls(
            id=d.get("id", _new_id()),
            queue_item_id=d["queue_item_id"],
            attempt_id=d.get("attempt_id", ""),
            proof_level=d.get("proof_level", "none"),
            artifacts=d.get("artifacts", []),
            impact_summary=d.get("impact_summary", ""),
            timestamp=d.get("timestamp", _now_iso()),
        )


@dataclass
class ValidationResult:
    """Resultado do ValidationGate após filtrar findings brutos."""
    accepted: List[Finding] = field(default_factory=list)
    rejected: List[Finding] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.accepted) + len(self.rejected)

    @property
    def acceptance_rate(self) -> float:
        if self.total == 0:
            return 0.0
        return len(self.accepted) / self.total


@dataclass
class StageStatus:
    """Status de execução de um estágio do workflow."""
    stage_name: str
    status: str = "not_started"             # "not_started", "running", "done", "skipped", "error"
    started_at: Optional[str] = None
    finished_at: Optional[str] = None
    error: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)

    def start(self):
        self.status = "running"
        self.started_at = _now_iso()

    def done(self, metrics: Optional[Dict[str, Any]] = None):
        self.status = "done"
        self.finished_at = _now_iso()
        if metrics:
            self.metrics.update(metrics)

    def skip(self, reason: str = ""):
        self.status = "skipped"
        self.finished_at = _now_iso()
        if reason:
            self.metrics["skip_reason"] = reason

    def fail(self, error: str):
        self.status = "error"
        self.finished_at = _now_iso()
        self.error = error

    def to_dict(self) -> Dict[str, Any]:
        return {
            "stage_name": self.stage_name,
            "status": self.status,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "error": self.error,
            "metrics": self.metrics,
        }
