import hashlib
import json
import sqlite3
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from .domain import ScoredEvent


class LogRepository:
    INTEGRITY_VERSION = 2
    def __init__(self, db_path: Path):
        self.db_path = db_path

    def initialize(self):
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    description TEXT,
                    status TEXT NOT NULL DEFAULT 'open',
                    created_at TEXT NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER,
                    case_name TEXT NOT NULL,
                    line_no INTEGER NOT NULL,
                    ingested_at TEXT NOT NULL,
                    event_time TEXT,
                    source_ip TEXT,
                    severity TEXT,
                    event_type TEXT,
                    risk_score REAL,
                    verdict TEXT,
                    explanation TEXT,
                    model_source TEXT,
                    raw_log TEXT NOT NULL,
                    previous_hash TEXT,
                    integrity_hash TEXT NOT NULL,
                    FOREIGN KEY (case_id) REFERENCES cases(id)
                )
                """
            )
            self._ensure_column(conn, "cases", "description", "TEXT")
            self._ensure_column(conn, "cases", "status", "TEXT NOT NULL DEFAULT 'open'")
            self._ensure_column(conn, "cases", "created_at", "TEXT")
            self._ensure_column(conn, "logs", "case_id", "INTEGER")
            self._ensure_column(conn, "logs", "explanation", "TEXT")
            # Version 1 hashes protected only raw_log. Version 2 protects every
            # evidence field persisted in a log record.
            self._ensure_column(conn, "logs", "integrity_version", "INTEGER NOT NULL DEFAULT 1")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_case_id ON logs(case_id)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_case_name ON logs(case_name)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_verdict ON logs(verdict)")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)")

    def create_case(self, title: str, description: str = "") -> Dict:
        created_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"

        with self._connect() as conn:
            columns = self._table_columns(conn, "cases")
            insert_values = {
                "title": title,
                "description": description,
                "status": "open",
                "created_at": created_at,
            }
            if "created_by" in columns:
                insert_values["created_by"] = "single-analyst"
            if "assigned_to" in columns:
                insert_values["assigned_to"] = None

            insert_columns = [column for column in insert_values if column in columns]
            placeholders = ", ".join("?" for _ in insert_columns)
            cursor = conn.execute(
                f"""
                INSERT INTO cases ({", ".join(insert_columns)})
                VALUES ({placeholders})
                """,
                [insert_values[column] for column in insert_columns],
            )
            case_id = cursor.lastrowid

        return self.get_case(case_id)

    def list_cases(self) -> List[Dict]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT cases.*, COUNT(logs.id) AS log_count
                FROM cases
                LEFT JOIN logs ON logs.case_id = cases.id
                GROUP BY cases.id
                ORDER BY cases.id DESC
                """
            ).fetchall()

        return [dict(row) for row in rows]

    def get_case(self, case_id: int) -> Optional[Dict]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
        return dict(row) if row else None

    def case_exists(self, case_id: int) -> bool:
        return self.get_case(case_id) is not None

    def user_can_access_case(
        self,
        case_id: int,
        username: Optional[str] = None,
        role: Optional[str] = None,
    ) -> bool:
        return self.case_exists(case_id)

    def save_events(self, case_id: int, events: List[ScoredEvent]):
        ingested_at = datetime.utcnow().isoformat(timespec="seconds") + "Z"
        case = self.get_case(case_id)
        if not case:
            raise ValueError("Case not found")

        with self._connect() as conn:
            previous_hash = self._latest_hash(conn, case_id)
            for event in events:
                integrity_hash = self.chain_hash(
                    self._event_integrity_payload(case_id, case["title"], ingested_at, event),
                    previous_hash,
                    self.INTEGRITY_VERSION,
                )
                conn.execute(
                    """
                    INSERT INTO logs (
                        case_id, case_name, line_no, ingested_at, event_time, source_ip, severity,
                        event_type, risk_score, verdict, explanation, model_source, raw_log,
                        previous_hash, integrity_hash, integrity_version
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        case_id,
                        case["title"],
                        event.line_no,
                        ingested_at,
                        event.timestamp,
                        event.source_ip,
                        event.severity,
                        event.event_type,
                        event.risk_score,
                        event.verdict,
                        event.explanation,
                        event.model_source,
                        event.raw_log,
                        previous_hash,
                        integrity_hash,
                        self.INTEGRITY_VERSION,
                    ),
                )
                previous_hash = integrity_hash

    def query_events(self, case_id: int, filters: Dict, limit: int = 250) -> List[Dict]:
        clauses = ["case_id = ?"]
        values = [case_id]

        if filters.get("search"):
            clauses.append("raw_log LIKE ?")
            values.append(f"%{filters['search']}%")
        if filters.get("verdict"):
            clauses.append("verdict = ?")
            values.append(filters["verdict"])
        if filters.get("severity"):
            clauses.append("severity = ?")
            values.append(filters["severity"])
        if filters.get("source_ip"):
            clauses.append("source_ip = ?")
            values.append(filters["source_ip"])
        if filters.get("event_type"):
            clauses.append("event_type = ?")
            values.append(filters["event_type"])

        where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
        values.append(limit)

        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT * FROM logs
                {where}
                ORDER BY id DESC
                LIMIT ?
                """,
                values,
            ).fetchall()

        return [dict(row) for row in rows]

    def clear_case_logs(self, case_id: int):
        with self._connect() as conn:
            conn.execute("DELETE FROM logs WHERE case_id = ?", (case_id,))

    def verify_case_chain(self, case_id: int) -> Dict:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, case_id, case_name, line_no, ingested_at, event_time, source_ip, severity,
                       event_type, risk_score, verdict, explanation, model_source, raw_log,
                       previous_hash, integrity_hash, integrity_version
                FROM logs
                WHERE case_id = ?
                ORDER BY id ASC
                """,
                (case_id,),
            ).fetchall()

        previous_hash = ""
        checked = 0
        failures = []
        legacy_logs = 0
        for row in rows:
            integrity_version = row["integrity_version"] or 1
            if integrity_version >= self.INTEGRITY_VERSION:
                payload = self._stored_event_integrity_payload(row)
            else:
                # Keep historical chains verifiable, but report that their
                # coverage is limited to the original raw log text.
                payload = row["raw_log"]
                legacy_logs += 1
            expected_hash = self.chain_hash(payload, previous_hash, integrity_version)
            if row["previous_hash"] != previous_hash or row["integrity_hash"] != expected_hash:
                failures.append(
                    {
                        "log_id": row["id"],
                        "expected_previous_hash": previous_hash,
                        "stored_previous_hash": row["previous_hash"],
                        "expected_integrity_hash": expected_hash,
                        "stored_integrity_hash": row["integrity_hash"],
                    }
                )
            previous_hash = row["integrity_hash"]
            checked += 1

        return {
            "case_id": case_id,
            "valid": not failures,
            "checked_logs": checked,
            "failures": failures,
            "legacy_logs": legacy_logs,
            "integrity_coverage": "full_record" if not legacy_logs else "raw_log_only_for_legacy_records",
        }

    def _connect(self):
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _latest_hash(self, conn, case_id: int) -> str:
        previous = conn.execute(
            "SELECT integrity_hash FROM logs WHERE case_id = ? ORDER BY id DESC LIMIT 1",
            (case_id,),
        ).fetchone()
        return previous["integrity_hash"] if previous else ""

    def chain_hash(self, evidence_payload: str, previous_hash: str = "", integrity_version: int = 1) -> str:
        # Preserve verification for hashes created before versioned, full-record
        # protection was introduced.
        prefix = f"v{integrity_version}|" if integrity_version >= self.INTEGRITY_VERSION else ""
        payload = f"{prefix}{previous_hash}|{evidence_payload}".encode("utf-8", errors="replace")
        return hashlib.sha256(payload).hexdigest()

    def _event_integrity_payload(self, case_id: int, case_name: str, ingested_at: str, event: ScoredEvent) -> str:
        return self._canonical_integrity_payload(
            {
                "case_id": case_id,
                "case_name": case_name,
                "line_no": event.line_no,
                "ingested_at": ingested_at,
                "event_time": event.timestamp,
                "source_ip": event.source_ip,
                "severity": event.severity,
                "event_type": event.event_type,
                "risk_score": event.risk_score,
                "verdict": event.verdict,
                "explanation": event.explanation,
                "model_source": event.model_source,
                "raw_log": event.raw_log,
            }
        )

    def _stored_event_integrity_payload(self, row) -> str:
        return self._canonical_integrity_payload(
            {
                "case_id": row["case_id"],
                "case_name": row["case_name"],
                "line_no": row["line_no"],
                "ingested_at": row["ingested_at"],
                "event_time": row["event_time"],
                "source_ip": row["source_ip"],
                "severity": row["severity"],
                "event_type": row["event_type"],
                "risk_score": row["risk_score"],
                "verdict": row["verdict"],
                "explanation": row["explanation"],
                "model_source": row["model_source"],
                "raw_log": row["raw_log"],
            }
        )

    @staticmethod
    def _canonical_integrity_payload(fields: Dict) -> str:
        normalized_fields = dict(fields)
        # SQLite may return an integral REAL value as 31.0 while an in-memory
        # scorer can supply 31. Normalize it so the protected representation is
        # stable across the write/read boundary.
        if normalized_fields["risk_score"] is not None:
            normalized_fields["risk_score"] = float(normalized_fields["risk_score"])
        return json.dumps(normalized_fields, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

    def _ensure_column(self, conn, table_name: str, column_name: str, column_type: str):
        columns = self._table_columns(conn, table_name)
        if column_name not in columns:
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}")

    def _table_columns(self, conn, table_name: str) -> List[str]:
        return [row["name"] for row in conn.execute(f"PRAGMA table_info({table_name})").fetchall()]
