import os
import time
from typing import List, Dict, Optional

try:
    import psycopg
    from psycopg.rows import dict_row
except Exception:  # pragma: no cover
    psycopg = None


class PostgresAttackLogDB:
    """Best-effort PostgreSQL persistence for detected attacks.

    If Postgres is not configured or connection fails, this module becomes a
    no-op (so the IDS continues running).
    """

    def __init__(self):
        self._enabled = False
        self._conninfo = None
        self._last_init_attempt = 0.0
        self._init_backoff_sec = 10

        self._table = os.getenv("POSTGRES_ATTACK_LOGS_TABLE", "attack_logs")
        self._init_from_env()
        if self._enabled:
            self._ensure_schema_best_effort()

    def _init_from_env(self):
        host = os.getenv("POSTGRES_HOST")
        port = os.getenv("POSTGRES_PORT", "5432")
        dbname = os.getenv("POSTGRES_DB")
        user = os.getenv("POSTGRES_USER")
        password = os.getenv("POSTGRES_PASSWORD")

        # Enable only when all vars exist
        if not (host and dbname and user and password):
            self._enabled = False
            return

        if psycopg is None:
            self._enabled = False
            return

        self._conninfo = {
            "host": host,
            "port": int(port),
            "dbname": dbname,
            "user": user,
            "password": password,
            "connect_timeout": 5,
        }
        self._enabled = True

    def _ensure_schema_best_effort(self):
        if not self._enabled:
            return

        now = time.time()
        if now - self._last_init_attempt < self._init_backoff_sec:
            return
        self._last_init_attempt = now

        try:
            with psycopg.connect(**self._conninfo) as conn:
                conn.execute(
                    f"""
                    CREATE TABLE IF NOT EXISTS {self._table} (
                        id BIGSERIAL PRIMARY KEY,
                        timestamp TIMESTAMPTZ,
                        attack_type TEXT NOT NULL,
                        message TEXT NOT NULL,
                        source_ip TEXT,
                        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
                    );
                    """
                )
                conn.execute(
                    f"CREATE INDEX IF NOT EXISTS {self._table}_created_at_desc_idx "
                    f"ON {self._table} (created_at DESC);"
                )
                conn.commit()
        except Exception:
            # Keep no-op on failures.
            self._enabled = False

    def insert_attack_log(
        self,
        attack_type: str,
        message: str,
        source_ip: str = "",
        timestamp=None,
    ) -> None:
        """Insert a single attack log row.

        timestamp: optional datetime-like; if omitted, DB default is used.
        """
        if not self._enabled:
            # try a re-init later
            self._ensure_schema_best_effort()
            if not self._enabled:
                return

        try:
            with psycopg.connect(**self._conninfo) as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute(
                        f"""
                        INSERT INTO {self._table}
                            (timestamp, attack_type, message, source_ip)
                        VALUES (%s, %s, %s, %s)
                        """,
                        (timestamp, attack_type, message, source_ip or None),
                    )
                conn.commit()
        except Exception:
            # Disable until next retry
            self._enabled = False

    def fetch_attack_logs(self, limit: int = 50) -> List[Dict]:
        if not self._enabled:
            self._ensure_schema_best_effort()
            if not self._enabled:
                return []

        try:
            with psycopg.connect(**self._conninfo) as conn:
                with conn.cursor(row_factory=dict_row) as cur:
                    cur.execute(
                        f"""
                        SELECT timestamp, attack_type, message, source_ip, created_at
                        FROM {self._table}
                        ORDER BY created_at DESC
                        LIMIT %s
                        """,
                        (limit,),
                    )
                    rows = cur.fetchall()

            out = []
            for r in rows:
                out.append(
                    {
                        "timestamp": (r.get("timestamp").isoformat(timespec="seconds") if r.get("timestamp") else "--"),
                        "type": r.get("attack_type"),
                        "message": r.get("message"),
                        "source_ip": r.get("source_ip") or "Unknown",
                        "created_at": (r.get("created_at").isoformat(timespec="seconds") if r.get("created_at") else None),
                    }
                )
            return out
        except Exception:
            self._enabled = False
            return []


# Global singleton for app usage
postgres_attack_logs = PostgresAttackLogDB()

