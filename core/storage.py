"""
Persistencia local em SQLite para execucoes do ReconForge.
"""

import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


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
