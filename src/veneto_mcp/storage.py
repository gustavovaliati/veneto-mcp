"""Where the OAuth state lives: a table in the app's own database (no Redis), encrypted.

`kv_table(metadata)` declares the table on the app's SQLAlchemy metadata, so the app's migrations
create it (Alembic autogenerate picks it up). `SQLStore(engine, table)` is a py-key-value store
over it (Postgres or SQLite), and `encrypted(store, key)` wraps it in Fernet, which is what
`build_mcp` wants: every value (client registrations, grants, codes) is ciphertext at rest.
"""

import base64
import hashlib
from collections.abc import Sequence
from datetime import UTC, datetime

from cryptography.fernet import Fernet
from key_value.aio._utils.managed_entry import ManagedEntry, dump_to_json, load_from_json
from key_value.aio.protocols import AsyncKeyValue
from key_value.aio.stores.base import BaseStore
from key_value.aio.wrappers.encryption import FernetEncryptionWrapper
from sqlalchemy import Column, DateTime, Index, MetaData, String, Table, Text, delete, select
from sqlalchemy.dialects import postgresql, sqlite
from sqlalchemy.ext.asyncio import AsyncEngine

DEFAULT_TABLE = "mcp_oauth_kv"
#: Expired rows are purged on every this-many writes.
_PURGE_EVERY = 200


def kv_table(metadata: MetaData, name: str = DEFAULT_TABLE) -> Table:
    """The key-value table, declared on `metadata` (so the app's migrations own it)."""
    return Table(
        name,
        metadata,
        Column("collection", String(255), primary_key=True),
        Column("key", Text, primary_key=True),
        Column("value", Text, nullable=False),
        Column("created_at", DateTime(timezone=True)),
        Column("expires_at", DateTime(timezone=True)),
        Index(f"ix_{name}_expires_at", "expires_at"),
    )


def _aware(value: datetime | None) -> datetime | None:
    # SQLite hands timezone-aware columns back naive.
    if value is not None and value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value


class SQLStore(BaseStore):
    """A py-key-value store over `kv_table`, on the app's async engine."""

    def __init__(self, engine: AsyncEngine, table: Table) -> None:
        super().__init__(default_collection="default", stable_api=True)
        self._engine = engine
        self._table = table
        self._writes = 0
        dialect = engine.dialect.name
        if dialect == "postgresql":
            self._insert = postgresql.insert
        elif dialect == "sqlite":
            self._insert = sqlite.insert
        else:
            raise ValueError(f"SQLStore supports postgresql and sqlite, not {dialect}")

    async def _get_managed_entry(self, *, collection: str, key: str) -> ManagedEntry | None:
        t = self._table
        async with self._engine.connect() as conn:
            row = (
                await conn.execute(
                    select(t.c.value, t.c.created_at, t.c.expires_at).where(
                        t.c.collection == collection, t.c.key == key
                    )
                )
            ).first()
        if row is None:
            return None
        return ManagedEntry(
            value=load_from_json(row.value),
            created_at=_aware(row.created_at),
            expires_at=_aware(row.expires_at),
        )

    async def _get_managed_entries(
        self, *, collection: str, keys: Sequence[str]
    ) -> list[ManagedEntry | None]:
        return [await self._get_managed_entry(collection=collection, key=key) for key in keys]

    async def _put_managed_entry(
        self, *, collection: str, key: str, managed_entry: ManagedEntry
    ) -> None:
        values = {
            "collection": collection,
            "key": key,
            "value": dump_to_json(managed_entry.value_as_dict),
            "created_at": managed_entry.created_at,
            "expires_at": managed_entry.expires_at,
        }
        statement = self._insert(self._table).values(**values)
        statement = statement.on_conflict_do_update(
            index_elements=["collection", "key"],
            set_={k: statement.excluded[k] for k in ("value", "created_at", "expires_at")},
        )
        async with self._engine.begin() as conn:
            await conn.execute(statement)
        self._writes += 1
        if self._writes % _PURGE_EVERY == 0:
            await self.purge_expired()

    async def _delete_managed_entry(self, *, key: str, collection: str) -> bool:
        t = self._table
        async with self._engine.begin() as conn:
            result = await conn.execute(
                delete(t).where(t.c.collection == collection, t.c.key == key)
            )
        return result.rowcount > 0

    async def purge_expired(self) -> int:
        """Delete the rows whose TTL has passed; returns how many."""
        t = self._table
        async with self._engine.begin() as conn:
            result = await conn.execute(delete(t).where(t.c.expires_at <= datetime.now(UTC)))
        return result.rowcount


def fernet_key(secret: str) -> bytes:
    """A Fernet key derived from any high-entropy secret (>= 32 chars)."""
    if len(secret) < 32:
        raise ValueError("the storage encryption secret must be at least 32 characters")
    digest = hashlib.sha256(b"veneto-mcp storage v1\0" + secret.encode()).digest()
    return base64.urlsafe_b64encode(digest)


def encrypted(store: AsyncKeyValue, secret: str) -> AsyncKeyValue:
    """`store`, with every value Fernet-encrypted under a key derived from `secret`. A value that
    no longer decrypts (the secret was rotated) reads as missing: connectors sign in again."""
    return FernetEncryptionWrapper(
        key_value=store, fernet=Fernet(fernet_key(secret)), raise_on_decryption_error=False
    )
