"""A small FastAPI app with the remote MCP mounted: SQLite-backed encrypted storage, a fake
Telegram, and an in-memory user table the app's `sign_in`/`resolve` consult."""

import secrets
from contextlib import asynccontextmanager
from dataclasses import dataclass, field

import httpx
import pytest
from fastapi import FastAPI
from sqlalchemy import MetaData, Table
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from veneto_mcp import (
    ConnectorClient,
    Identity,
    SQLStore,
    build_mcp,
    encrypted,
    kv_table,
    telegram,
)
from veneto_mcp.testing import FakeProvider, running

BASE_URL = "https://mcp.test"
ALICE = 111
BOB = 222
STRANGER = 999


@dataclass
class Users:
    active: set[int] = field(default_factory=lambda: {ALICE, BOB})
    grants: dict[str, int] = field(default_factory=dict)
    sign_ins: list[tuple[Identity, ConnectorClient]] = field(default_factory=list)
    #: Make sign_in raise (the app's database is down, say).
    broken: bool = False

    async def sign_in(self, identity: Identity, client: ConnectorClient) -> str | None:
        self.sign_ins.append((identity, client))
        if self.broken:
            raise RuntimeError("db down, token connector: Alice")
        user = int(identity.subject)
        if user not in self.active:
            return None
        grant = "grant_" + secrets.token_urlsafe(16)
        self.grants[grant] = user
        return grant

    async def resolve(self, grant: str) -> int | None:
        user = self.grants.get(grant)
        return user if user in self.active else None


@pytest.fixture
def users() -> Users:
    return Users()


@pytest.fixture
def provider() -> FakeProvider:
    return FakeProvider()


@dataclass
class Db:
    engine: AsyncEngine
    table: Table

    def store(self) -> SQLStore:
        return SQLStore(self.engine, self.table)


@pytest.fixture
async def db(tmp_path):
    engine = create_async_engine(f"sqlite+aiosqlite:///{tmp_path / 'kv.db'}")
    metadata = MetaData()
    table = kv_table(metadata)
    async with engine.begin() as conn:
        await conn.run_sync(metadata.create_all)
    yield Db(engine, table)
    await engine.dispose()


@pytest.fixture
def remote(users, provider, db):
    remote = build_mcp(
        "test",
        instructions="Test tools.",
        base_url=BASE_URL,
        login=provider.login(telegram("424242", "telegram-client-secret")),
        sign_in=users.sign_in,
        resolve=users.resolve,
        storage=encrypted(db.store(), "s" * 40),
        jwt_signing_key="j" * 40,
    )

    @remote.server.tool()
    async def whoami() -> dict:
        """The signed-in user."""
        return {"user": await remote.principal()}

    return remote


@pytest.fixture
def app(remote):
    started = []

    @asynccontextmanager
    async def lifespan(_app):
        started.append(True)
        yield

    application = FastAPI(lifespan=lifespan)
    application.state.started = started

    @application.get("/api/hello")
    async def hello() -> dict:
        return {"hello": "world"}

    remote.mount(application)
    return application


@pytest.fixture
async def client(app):
    async with (
        running(app),
        httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE_URL) as c,
    ):
        yield c
