"""
Persistencia local em SQLite para execucoes do ReconForge.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from core.models import Finding, QueueItem, ExploitAttempt, Evidence


class Storage:
    """Persistencia de execucoes e cache de plugins"""

    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS runs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    context_json TEXT NOT NULL,
                    results_json TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS plugin_cache (
                    target TEXT NOT NULL,
                    plugin_name TEXT NOT NULL,
                    result_json TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    PRIMARY KEY (target, plugin_name)
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_runs_target ON runs(target)"
            )

            # ----------------------------------------------------------------
            # Tabelas do pipeline — Fase 1
            # ----------------------------------------------------------------
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    run_id INTEGER REFERENCES runs(id) ON DELETE CASCADE,
                    category TEXT NOT NULL,
                    target TEXT NOT NULL,
                    endpoint TEXT,
                    method TEXT,
                    parameter TEXT,
                    context TEXT,
                    candidate_payload TEXT,
                    detection_source TEXT,
                    raw_evidence TEXT,
                    confidence_score REAL DEFAULT 0.5,
                    externally_exploitable INTEGER DEFAULT 1,
                    stage TEXT DEFAULT 'detected',
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_run ON findings(run_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_findings_category ON findings(category)"
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS queue_items (
                    id TEXT PRIMARY KEY,
                    finding_id TEXT REFERENCES findings(id),
                    run_id INTEGER REFERENCES runs(id) ON DELETE CASCADE,
                    category TEXT NOT NULL,
                    priority INTEGER DEFAULT 5,
                    status TEXT DEFAULT 'pending',
                    assigned_executor TEXT,
                    target TEXT,
                    endpoint TEXT,
                    method TEXT,
                    parameter TEXT,
                    context TEXT,
                    candidate_payload TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_queue_run ON queue_items(run_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_queue_status ON queue_items(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_queue_category ON queue_items(category)"
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS exploit_attempts (
                    id TEXT PRIMARY KEY,
                    queue_item_id TEXT REFERENCES queue_items(id),
                    attempt_number INTEGER NOT NULL,
                    payload_used TEXT,
                    executor TEXT,
                    request_snapshot TEXT,
                    response_snapshot TEXT,
                    status TEXT DEFAULT 'failed',
                    error TEXT,
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_attempts_queue ON exploit_attempts(queue_item_id)"
            )

            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS evidences (
                    id TEXT PRIMARY KEY,
                    queue_item_id TEXT REFERENCES queue_items(id),
                    attempt_id TEXT REFERENCES exploit_attempts(id),
                    proof_level TEXT DEFAULT 'none',
                    artifacts_json TEXT,
                    impact_summary TEXT,
                    timestamp TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidences_queue ON evidences(queue_item_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_evidences_proof ON evidences(proof_level)"
            )

    def create_run(self, target: str, context: Dict[str, Any], results: Dict[str, Any]) -> int:
        now = datetime.now().isoformat()
        context_json = json.dumps(context, ensure_ascii=False, default=str)
        results_json = json.dumps(results, ensure_ascii=False, default=str)
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO runs (target, started_at, updated_at, context_json, results_json)
                VALUES (?, ?, ?, ?, ?)
                """,
                (target, now, now, context_json, results_json)
            )
            return int(cur.lastrowid)

    def update_run(self, run_id: int, context: Dict[str, Any], results: Dict[str, Any]) -> None:
        now = datetime.now().isoformat()
        context_json = json.dumps(context, ensure_ascii=False, default=str)
        results_json = json.dumps(results, ensure_ascii=False, default=str)
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE runs
                SET updated_at = ?, context_json = ?, results_json = ?
                WHERE id = ?
                """,
                (now, context_json, results_json, run_id)
            )

    def load_latest_run(self, target: str) -> Optional[Tuple[int, Dict[str, Any], Dict[str, Any]]]:
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT * FROM runs
                WHERE target = ?
                ORDER BY updated_at DESC
                LIMIT 1
                """,
                (target,)
            ).fetchone()
            if not row:
                return None
            context = json.loads(row["context_json"]) if row["context_json"] else {}
            results = json.loads(row["results_json"]) if row["results_json"] else {}
            return int(row["id"]), context, results

    def load_run_by_id(self, run_id: int) -> Optional[Tuple[int, Dict[str, Any], Dict[str, Any], str]]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM runs WHERE id = ?",
                (run_id,)
            ).fetchone()
            if not row:
                return None
            context = json.loads(row["context_json"]) if row["context_json"] else {}
            results = json.loads(row["results_json"]) if row["results_json"] else {}
            return int(row["id"]), context, results, str(row["target"])

    def list_targets(self) -> List[str]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT DISTINCT target FROM runs ORDER BY target"
            ).fetchall()
            return [row["target"] for row in rows]

    def list_targets_with_ids(self) -> List[Tuple[int, str, str]]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT r.id, r.target, r.updated_at
                FROM runs r
                JOIN (
                    SELECT target, MAX(updated_at) AS max_updated
                    FROM runs
                    GROUP BY target
                ) latest ON r.target = latest.target AND r.updated_at = latest.max_updated
                ORDER BY r.target
                """
            ).fetchall()
            return [(int(row["id"]), str(row["target"]), str(row["updated_at"])) for row in rows]

    def delete_target(self, target: str) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM runs WHERE target = ?", (target,))
            conn.execute("DELETE FROM plugin_cache WHERE target = ?", (target,))

    def get_cached_result(self, target: str, plugin_name: str, ttl_seconds: int = 3600) -> Optional[Dict[str, Any]]:
        """Retorna resultado em cache se existir e não estiver expirado (TTL)."""
        with self._connect() as conn:
            row = conn.execute(
                """
                SELECT result_json, updated_at FROM plugin_cache
                WHERE target = ? AND plugin_name = ?
                """,
                (target, plugin_name)
            ).fetchone()
            if not row:
                return None
            # Verificar TTL — invalidar resultados antigos
            if ttl_seconds > 0:
                try:
                    updated = datetime.fromisoformat(row["updated_at"])
                    age = (datetime.now() - updated).total_seconds()
                    if age > ttl_seconds:
                        return None  # Cache expirado
                except (ValueError, TypeError):
                    pass  # Se falhar o parse, retorna o cache
            return json.loads(row["result_json"])

    def set_cached_result(self, target: str, plugin_name: str, result: Dict[str, Any]) -> None:
        now = datetime.now().isoformat()
        result_json = json.dumps(result, ensure_ascii=False, default=str)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO plugin_cache (target, plugin_name, result_json, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(target, plugin_name) DO UPDATE SET
                    result_json = excluded.result_json,
                    updated_at = excluded.updated_at
                """,
                (target, plugin_name, result_json, now)
            )

    # -----------------------------------------------------------------------
    # Findings
    # -----------------------------------------------------------------------

    def save_finding(self, finding: "Finding") -> None:
        """Persiste ou atualiza um Finding."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO findings
                (id, run_id, category, target, endpoint, method, parameter, context,
                 candidate_payload, detection_source, raw_evidence, confidence_score,
                 externally_exploitable, stage, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    finding.id, finding.run_id, finding.category, finding.target,
                    finding.endpoint, finding.method, finding.parameter, finding.context,
                    finding.candidate_payload, finding.detection_source, finding.raw_evidence,
                    finding.confidence_score, int(finding.externally_exploitable),
                    finding.stage, finding.created_at,
                ),
            )

    def save_findings(self, findings: List) -> None:
        """Persiste uma lista de Findings em transação única."""
        for f in findings:
            self.save_finding(f)

    def load_findings(self, run_id: int) -> List[Dict[str, Any]]:
        """Retorna todos os findings de um run como dicionários."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM findings WHERE run_id = ? ORDER BY created_at",
                (run_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    def update_finding_stage(self, finding_id: str, stage: str) -> None:
        """Atualiza o estágio de um finding (ex: detected → validated)."""
        with self._connect() as conn:
            conn.execute(
                "UPDATE findings SET stage = ? WHERE id = ?",
                (stage, finding_id),
            )

    # -----------------------------------------------------------------------
    # Queue Items
    # -----------------------------------------------------------------------

    def save_queue_item(self, item: "QueueItem") -> None:
        """Persiste ou atualiza um QueueItem."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO queue_items
                (id, finding_id, run_id, category, priority, status, assigned_executor,
                 target, endpoint, method, parameter, context, candidate_payload,
                 created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    item.id, item.finding_id, item.run_id, item.category, item.priority,
                    item.status, item.assigned_executor, item.target, item.endpoint,
                    item.method, item.parameter, item.context, item.candidate_payload,
                    item.created_at, item.updated_at,
                ),
            )

    def save_queue_items(self, items: List) -> None:
        """Persiste uma lista de QueueItems em transação única."""
        for item in items:
            self.save_queue_item(item)

    def load_queue_items(self, run_id: int, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retorna queue items de um run, filtrado opcionalmente por status."""
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM queue_items WHERE run_id = ? AND status = ? ORDER BY priority, created_at",
                    (run_id, status),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM queue_items WHERE run_id = ? ORDER BY priority, created_at",
                    (run_id,),
                ).fetchall()
            return [dict(row) for row in rows]

    def update_queue_item_status(self, item_id: str, status: str) -> None:
        """Atualiza status de um QueueItem."""
        now = datetime.now().isoformat()
        with self._connect() as conn:
            conn.execute(
                "UPDATE queue_items SET status = ?, updated_at = ? WHERE id = ?",
                (status, now, item_id),
            )

    # -----------------------------------------------------------------------
    # Exploit Attempts
    # -----------------------------------------------------------------------

    def save_attempt(self, attempt: "ExploitAttempt") -> None:
        """Persiste uma tentativa de exploit."""
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO exploit_attempts
                (id, queue_item_id, attempt_number, payload_used, executor,
                 request_snapshot, response_snapshot, status, error, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    attempt.id, attempt.queue_item_id, attempt.attempt_number,
                    attempt.payload_used, attempt.executor, attempt.request_snapshot,
                    attempt.response_snapshot, attempt.status, attempt.error,
                    attempt.timestamp,
                ),
            )

    def load_attempts(self, queue_item_id: str) -> List[Dict[str, Any]]:
        """Retorna todas as tentativas de um QueueItem."""
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM exploit_attempts WHERE queue_item_id = ? ORDER BY attempt_number",
                (queue_item_id,),
            ).fetchall()
            return [dict(row) for row in rows]

    # -----------------------------------------------------------------------
    # Evidences
    # -----------------------------------------------------------------------

    def save_evidence(self, evidence: "Evidence") -> None:
        """Persiste uma evidência coletada."""
        artifacts_json = json.dumps(evidence.artifacts, ensure_ascii=False)
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO evidences
                (id, queue_item_id, attempt_id, proof_level, artifacts_json,
                 impact_summary, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    evidence.id, evidence.queue_item_id, evidence.attempt_id,
                    evidence.proof_level, artifacts_json, evidence.impact_summary,
                    evidence.timestamp,
                ),
            )

    def load_evidences(self, run_id: int, proof_level: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retorna evidências de um run, filtrado opcionalmente por proof_level."""
        with self._connect() as conn:
            if proof_level:
                rows = conn.execute(
                    """
                    SELECT e.* FROM evidences e
                    JOIN queue_items q ON e.queue_item_id = q.id
                    WHERE q.run_id = ? AND e.proof_level = ?
                    ORDER BY e.timestamp
                    """,
                    (run_id, proof_level),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT e.* FROM evidences e
                    JOIN queue_items q ON e.queue_item_id = q.id
                    WHERE q.run_id = ?
                    ORDER BY e.timestamp
                    """,
                    (run_id,),
                ).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                d["artifacts"] = json.loads(d.pop("artifacts_json", "[]") or "[]")
                result.append(d)
            return result

    # -----------------------------------------------------------------------
    # Checkpoint de WorkflowState
    # -----------------------------------------------------------------------

    def checkpoint_workflow(self, state: Any) -> None:
        """
        Faz checkpoint completo do WorkflowState no banco:
        - Atualiza o run com o contexto atual.
        - Persiste findings, queue_items, attempts e evidences novos.
        """
        if state.run_id < 0:
            return

        # Atualizar run principal
        self.update_run(state.run_id, state.to_context_dict(), {})

        # Persistir findings novos
        self.save_findings(state.findings)
        self.save_findings(state.rejected_findings)

        # Persistir queue items
        self.save_queue_items(state.queue_items)

        # Persistir attempts
        for attempt in state.attempts:
            self.save_attempt(attempt)

        # Persistir evidências
        for evidence in state.evidences:
            self.save_evidence(evidence)

    def get_run_summary(self, run_id: int) -> Dict[str, Any]:
        """Retorna resumo executivo de um run com contagens dos modelos do pipeline."""
        with self._connect() as conn:
            run_row = conn.execute(
                "SELECT target, started_at, updated_at FROM runs WHERE id = ?",
                (run_id,),
            ).fetchone()
            if not run_row:
                return {}

            findings_count = conn.execute(
                "SELECT COUNT(*) as n FROM findings WHERE run_id = ?", (run_id,)
            ).fetchone()["n"]

            validated_count = conn.execute(
                "SELECT COUNT(*) as n FROM findings WHERE run_id = ? AND stage = 'validated'",
                (run_id,),
            ).fetchone()["n"]

            queue_count = conn.execute(
                "SELECT COUNT(*) as n FROM queue_items WHERE run_id = ?", (run_id,)
            ).fetchone()["n"]

            confirmed_count = conn.execute(
                """
                SELECT COUNT(*) as n FROM evidences e
                JOIN queue_items q ON e.queue_item_id = q.id
                WHERE q.run_id = ? AND e.proof_level = 'impact_proven'
                """,
                (run_id,),
            ).fetchone()["n"]

            return {
                "run_id": run_id,
                "target": run_row["target"],
                "started_at": run_row["started_at"],
                "updated_at": run_row["updated_at"],
                "findings_total": findings_count,
                "findings_validated": validated_count,
                "queue_items": queue_count,
                "evidence_confirmed": confirmed_count,
            }
