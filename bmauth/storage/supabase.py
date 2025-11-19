"""
Supabase-backed storage implementation for BMAuth.
"""
from __future__ import annotations

import os
from typing import Any, Dict, Optional

from .base import StorageBackend, StorageError


class SupabaseStorage(StorageBackend):
    """
    Storage backend that persists BMAuth state in Supabase/Postgres.
    """

    def __init__(
        self,
        url: str,
        key: str,
        *,
        schema: Optional[str] = None,
        table_prefix: str = "bmauth_",
    ) -> None:
        try:
            from supabase import Client, create_client  # type: ignore
        except ImportError as exc:  # pragma: no cover - import guard
            raise StorageError(
                "Supabase support requires the 'supabase' package. "
                "Install the optional dependency with `pip install bmauth[supabase]`."
            ) from exc

        self._client: Client = create_client(url, key)
        self._schema = schema or "public"
        if schema:
            self._client.postgrest.schema = schema

        self._tables = {
            "users": f"{table_prefix}users",
            "challenges": f"{table_prefix}challenges",
            "pins": f"{table_prefix}verification_pins",
            "device_sessions": f"{table_prefix}device_sessions",
        }
        self._table_prefix = table_prefix
        self._debug_last_errors: Dict[str, str] = {}

    # region helpers
    def _execute(self, query, action: str) -> Any:
        try:
            response = query.execute()
        except Exception as exc:
            self._debug_last_errors[action] = str(exc)
            raise StorageError(f"Supabase {action} failed: {exc}") from exc

        if getattr(response, "error", None):  # supabase-py <2
            raise StorageError(f"Supabase {action} error: {response.error}")

        return getattr(response, "data", None)

    def _single(self, table: str, key: str, value: str) -> Optional[Dict[str, Any]]:
        data = self._execute(
            self._client.table(table).select("*").eq(key, value).limit(1),
            f"select from {table}",
        )
        if not data:
            return None
        return data[0]

    # endregion

    # region StorageBackend implementation
    def get_user(self, email: str) -> Optional[Dict[str, Any]]:
        row = self._single(self._tables["users"], "email", email)
        if not row:
            return None
        return row.get("payload") or {}

    def save_user(self, email: str, payload: Dict[str, Any]) -> None:
        self._execute(
            self._client.table(self._tables["users"]).upsert(
                {"email": email, "payload": payload}, on_conflict="email"
            ),
            "upsert user",
        )

    def delete_user(self, email: str) -> None:
        self._execute(
            self._client.table(self._tables["users"]).delete().eq("email", email),
            "delete user",
        )

    def get_challenge(self, email: str) -> Optional[str]:
        row = self._single(self._tables["challenges"], "email", email)
        if not row:
            return None
        return row.get("challenge")

    def set_challenge(self, email: str, challenge: str) -> None:
        self._execute(
            self._client.table(self._tables["challenges"]).upsert(
                {"email": email, "challenge": challenge}, on_conflict="email"
            ),
            "upsert challenge",
        )

    def delete_challenge(self, email: str) -> None:
        self._execute(
            self._client.table(self._tables["challenges"]).delete().eq("email", email),
            "delete challenge",
        )

    def get_verification_pin(self, email: str) -> Optional[Dict[str, Any]]:
        row = self._single(self._tables["pins"], "email", email)
        if not row:
            return None
        return row.get("payload") or {}

    def set_verification_pin(self, email: str, payload: Dict[str, Any]) -> None:
        self._execute(
            self._client.table(self._tables["pins"]).upsert(
                {"email": email, "payload": payload}, on_conflict="email"
            ),
            "upsert verification pin",
        )

    def delete_verification_pin(self, email: str) -> None:
        self._execute(
            self._client.table(self._tables["pins"]).delete().eq("email", email),
            "delete verification pin",
        )

    def get_device_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        row = self._single(
            self._tables["device_sessions"], "session_id", session_id
        )
        if not row:
            return None
        return row.get("payload") or {}

    def set_device_session(self, session_id: str, payload: Dict[str, Any]) -> None:
        self._execute(
            self._client.table(self._tables["device_sessions"]).upsert(
                {"session_id": session_id, "payload": payload},
                on_conflict="session_id",
            ),
            "upsert device session",
        )

    def delete_device_session(self, session_id: str) -> None:
        self._execute(
            self._client.table(self._tables["device_sessions"])
            .delete()
            .eq("session_id", session_id),
            "delete device session",
        )

    # endregion

    # region Utilities
    def debug_snapshot(self) -> Dict[str, Any]:
        tables: Dict[str, Any] = {}
        for alias, table_name in self._tables.items():
            try:
                response = self._client.table(table_name).select("*").execute()
            except Exception as exc:  # noqa: BLE001
                tables[alias] = {"error": str(exc)}
            else:
                data = getattr(response, "data", None)
                tables[alias] = data if isinstance(data, list) else []

        return {
            "backend": "supabase",
            "schema": self._schema,
            "tables": tables,
            "last_errors": {k: str(v) for k, v in self._debug_last_errors.items()},
            "hint": "If tables are missing, execute SupabaseStorage.schema_sql() in your Supabase project.",
        }

    def ensure_tables(self, dsn: Optional[str] = None) -> None:
        """
        Create the required tables if they are missing.
        """

        dsn = (
            dsn
            or os.getenv("SUPABASE_DB_URL")
        )
        if not dsn:
            raise StorageError(
                "Auto table creation requires a Postgres connection string. "
                "Set SUPABASE_DB_URL or pass 'postgres_dsn' in the database config."
            )

        try:
            import psycopg  # type: ignore
        except ImportError as exc:  # pragma: no cover - import guard
            raise StorageError(
                "Auto table creation requires the 'psycopg' package. "
                "Install it with `pip install psycopg[binary]`."
            ) from exc

        ddl_statements = [stmt.strip() for stmt in self.schema_sql(self._table_prefix).split(";\n\n") if stmt.strip()]

        try:
            with psycopg.connect(dsn) as conn:  # type: ignore[attr-defined]
                conn.execute(f'SET search_path TO "{self._schema}";')
                for stmt in ddl_statements:
                    conn.execute(stmt + ";")
                conn.commit()
        except Exception as exc:  # pragma: no cover - depends on DB state
            raise StorageError(f"Failed to ensure Supabase tables exist: {exc}") from exc

    @staticmethod
    def schema_sql(table_prefix: str = "bmauth_") -> str:
        """
        Return the SQL DDL required for the storage tables.
        """

        users = f"{table_prefix}users"
        challenges = f"{table_prefix}challenges"
        pins = f"{table_prefix}verification_pins"
        sessions = f"{table_prefix}device_sessions"

        return f"""
CREATE TABLE IF NOT EXISTS {users} (
    email TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now()),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE TABLE IF NOT EXISTS {challenges} (
    email TEXT PRIMARY KEY,
    challenge TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE TABLE IF NOT EXISTS {pins} (
    email TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);

CREATE TABLE IF NOT EXISTS {sessions} (
    session_id TEXT PRIMARY KEY,
    payload JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT timezone('utc', now())
);
""".strip()

    # endregion

