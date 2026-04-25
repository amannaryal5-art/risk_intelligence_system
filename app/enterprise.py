from __future__ import annotations

import hashlib
import json
import os
import sqlite3
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass(frozen=True)
class UserContext:
    username: str
    role: str
    authenticated: bool
    api_key_hash: str


class AuthManager:
    def __init__(self) -> None:
        self._key_index = self._load_keys()

    def _load_keys(self) -> Dict[str, Dict[str, str]]:
        raw = os.getenv("RISKINTEL_API_KEYS", "").strip()
        out: Dict[str, Dict[str, str]] = {}
        allowed_roles = {"admin", "analyst", "viewer"}
        if raw:
            parts = [x.strip() for x in raw.split(",") if x.strip()]
            for p in parts:
                chunks = p.split(":")
                if len(chunks) != 3:
                    continue
                key, role, username = chunks
                role = role.strip().lower()
                if role not in allowed_roles:
                    continue
                out[key] = {"role": role, "username": username}
        return out

    @property
    def key_count(self) -> int:
        return len(self._key_index)

    @staticmethod
    def hash_key(api_key: str) -> str:
        return hashlib.sha256(api_key.encode("utf-8")).hexdigest()[:16]

    def identify(self, api_key: Optional[str]) -> UserContext:
        if not api_key:
            return UserContext(
                username="anonymous",
                role="anonymous",
                authenticated=False,
                api_key_hash="none",
            )
        rec = self._key_index.get(api_key)
        if not rec:
            return UserContext(
                username="invalid",
                role="invalid",
                authenticated=False,
                api_key_hash=self.hash_key(api_key),
            )
        return UserContext(
            username=rec["username"],
            role=rec["role"],
            authenticated=True,
            api_key_hash=self.hash_key(api_key),
        )


class CaseStore:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), timeout=10, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    source_type TEXT NOT NULL,
                    source_value TEXT,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    status TEXT NOT NULL,
                    assigned_to TEXT,
                    reporter TEXT NOT NULL,
                    findings_json TEXT NOT NULL,
                    tags_json TEXT NOT NULL,
                    recommendations_json TEXT NOT NULL
                )
                """
            )
            columns = {row["name"] for row in conn.execute("PRAGMA table_info(cases)").fetchall()}
            for column, sql in {
                "ioc_type": "ALTER TABLE cases ADD COLUMN ioc_type TEXT",
                "ioc_value": "ALTER TABLE cases ADD COLUMN ioc_value TEXT",
                "risk_score": "ALTER TABLE cases ADD COLUMN risk_score INTEGER",
                "scan_result_json": "ALTER TABLE cases ADD COLUMN scan_result_json TEXT NOT NULL DEFAULT '{}'",
                "notes": "ALTER TABLE cases ADD COLUMN notes TEXT",
            }.items():
                if column not in columns:
                    conn.execute(sql)
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS case_comments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    author TEXT NOT NULL,
                    message TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(id)
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_logs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    created_at TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    role TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target_type TEXT NOT NULL,
                    target_id TEXT,
                    meta_json TEXT NOT NULL
                )
                """
            )
            conn.commit()

    def audit(
        self,
        actor: str,
        role: str,
        action: str,
        target_type: str,
        target_id: Optional[str] = None,
        meta: Optional[Dict[str, Any]] = None,
    ) -> None:
        try:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO audit_logs(created_at, actor, role, action, target_type, target_id, meta_json)
                    VALUES(?,?,?,?,?,?,?)
                    """,
                    (
                        utc_now(),
                        actor,
                        role,
                        action,
                        target_type,
                        target_id,
                        json.dumps(meta or {}, ensure_ascii=True),
                    ),
                )
                conn.commit()
        except sqlite3.Error:
            # Do not block core detection flows due to audit write failures.
            return

    def create_case(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        now = utc_now()
        with self._conn() as conn:
            cur = conn.execute(
                """
                INSERT INTO cases(
                    created_at, updated_at, source_type, source_value, title, severity, status,
                    assigned_to, reporter, findings_json, tags_json, recommendations_json
                ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    now,
                    now,
                    payload["source_type"],
                    payload.get("source_value"),
                    payload["title"],
                    payload["severity"],
                    payload["status"],
                    payload.get("assigned_to"),
                    payload["reporter"],
                    json.dumps(payload.get("findings", {}), ensure_ascii=True),
                    json.dumps(payload.get("tags", []), ensure_ascii=True),
                    json.dumps(payload.get("recommendations", []), ensure_ascii=True),
                ),
            )
            conn.execute(
                """
                UPDATE cases
                SET ioc_type = ?, ioc_value = ?, risk_score = ?, scan_result_json = ?, notes = ?
                WHERE id = ?
                """,
                (
                    payload.get("ioc_type"),
                    payload.get("ioc_value"),
                    payload.get("risk_score"),
                    json.dumps(payload.get("scan_result", {}), ensure_ascii=True),
                    payload.get("notes"),
                    int(cur.lastrowid),
                ),
            )
            case_id = int(cur.lastrowid)
            conn.commit()
        return self.get_case(case_id)

    def list_cases(
        self, status: Optional[str], severity: Optional[str], assigned_to: Optional[str], limit: int, search: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        clauses = []
        params: List[Any] = []
        if status:
            clauses.append("status = ?")
            params.append(status)
        if severity:
            clauses.append("severity = ?")
            params.append(severity)
        if assigned_to:
            clauses.append("assigned_to = ?")
            params.append(assigned_to)
        if search:
            clauses.append("(title LIKE ? OR source_value LIKE ? OR ioc_value LIKE ?)")
            like = f"%{search}%"
            params.extend([like, like, like])
        where_sql = " WHERE " + " AND ".join(clauses) if clauses else ""
        sql = (
            "SELECT * FROM cases"
            + where_sql
            + " ORDER BY updated_at DESC LIMIT ?"
        )
        params.append(max(1, min(limit, 200)))
        with self._conn() as conn:
            rows = conn.execute(sql, params).fetchall()
        return [self._row_to_case(row, include_comments=False) for row in rows]

    def get_case(self, case_id: int) -> Dict[str, Any]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if row is None:
                raise KeyError(f"Case {case_id} not found")
            case = self._row_to_case(row, include_comments=False)
            comments = conn.execute(
                "SELECT * FROM case_comments WHERE case_id = ? ORDER BY created_at ASC",
                (case_id,),
            ).fetchall()
        case["comments"] = [self._row_to_comment(c) for c in comments]
        return case

    def update_case(self, case_id: int, updates: Dict[str, Any]) -> Dict[str, Any]:
        allowed = {"status", "severity", "assigned_to", "title", "tags", "recommendations", "notes"}
        fields = [k for k in updates.keys() if k in allowed and updates[k] is not None]
        if not fields:
            return self.get_case(case_id)
        sql_chunks = []
        params: List[Any] = []
        for f in fields:
            if f == "tags":
                sql_chunks.append("tags_json = ?")
                params.append(json.dumps(updates["tags"], ensure_ascii=True))
            elif f == "recommendations":
                sql_chunks.append("recommendations_json = ?")
                params.append(json.dumps(updates["recommendations"], ensure_ascii=True))
            elif f == "notes":
                sql_chunks.append("notes = ?")
                params.append(updates["notes"])
            else:
                sql_chunks.append(f"{f} = ?")
                params.append(updates[f])
        sql_chunks.append("updated_at = ?")
        params.append(utc_now())
        params.append(case_id)
        with self._conn() as conn:
            cur = conn.execute(f"UPDATE cases SET {', '.join(sql_chunks)} WHERE id = ?", params)
            if cur.rowcount == 0:
                raise KeyError(f"Case {case_id} not found")
            conn.commit()
        return self.get_case(case_id)

    def delete_case(self, case_id: int) -> None:
        with self._conn() as conn:
            conn.execute("DELETE FROM case_comments WHERE case_id = ?", (case_id,))
            cur = conn.execute("DELETE FROM cases WHERE id = ?", (case_id,))
            if cur.rowcount == 0:
                raise KeyError(f"Case {case_id} not found")
            conn.commit()

    def add_comment(self, case_id: int, author: str, message: str) -> Dict[str, Any]:
        created_at = utc_now()
        with self._conn() as conn:
            exists = conn.execute("SELECT id FROM cases WHERE id = ?", (case_id,)).fetchone()
            if not exists:
                raise KeyError(f"Case {case_id} not found")
            cur = conn.execute(
                "INSERT INTO case_comments(case_id, author, message, created_at) VALUES(?,?,?,?)",
                (case_id, author, message, created_at),
            )
            conn.execute("UPDATE cases SET updated_at = ? WHERE id = ?", (created_at, case_id))
            conn.commit()
            comment_id = int(cur.lastrowid)
        return {"id": comment_id, "case_id": case_id, "author": author, "message": message, "created_at": created_at}

    def list_audits(self, limit: int) -> List[Dict[str, Any]]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?",
                (max(1, min(limit, 500)),),
            ).fetchall()
        out = []
        for row in rows:
            out.append(
                {
                    "id": int(row["id"]),
                    "created_at": row["created_at"],
                    "actor": row["actor"],
                    "role": row["role"],
                    "action": row["action"],
                    "target_type": row["target_type"],
                    "target_id": row["target_id"],
                    "meta": json.loads(row["meta_json"] or "{}"),
                }
            )
        return out

    def _row_to_comment(self, row: sqlite3.Row) -> Dict[str, Any]:
        return {
            "id": int(row["id"]),
            "case_id": int(row["case_id"]),
            "author": row["author"],
            "message": row["message"],
            "created_at": row["created_at"],
        }

    def _row_to_case(self, row: sqlite3.Row, include_comments: bool) -> Dict[str, Any]:
        out = {
            "id": int(row["id"]),
            "created_at": row["created_at"],
            "updated_at": row["updated_at"],
            "source_type": row["source_type"],
            "source_value": row["source_value"],
            "title": row["title"],
            "severity": row["severity"],
            "status": row["status"],
            "assigned_to": row["assigned_to"],
            "reporter": row["reporter"],
            "ioc_type": row["ioc_type"] if "ioc_type" in row.keys() else None,
            "ioc_value": row["ioc_value"] if "ioc_value" in row.keys() else None,
            "risk_score": row["risk_score"] if "risk_score" in row.keys() else None,
            "findings": json.loads(row["findings_json"] or "{}"),
            "scan_result": json.loads(row["scan_result_json"] or "{}") if "scan_result_json" in row.keys() else {},
            "tags": json.loads(row["tags_json"] or "[]"),
            "recommendations": json.loads(row["recommendations_json"] or "[]"),
            "notes": row["notes"] if "notes" in row.keys() else None,
        }
        if include_comments:
            out["comments"] = []
        return out
