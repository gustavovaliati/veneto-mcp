"""Test helpers: a fake OIDC provider and a scripted browser for the sign-in flow.

    provider = FakeProvider()
    login = provider.login(telegram("123", "secret"))   # same preset, fake keys and endpoint
    ...build_mcp(..., login=login)...
    provider.next_claims = {"id": 111, "name": "Ana"}  # who "signs in" upstream
    tokens = await SignInFlow(client).connect()        # DCR, consent, callback, code exchange
    await mcp_call(client, tokens["access_token"], "tools/list")

No network: the token endpoint answers from an `httpx2.MockTransport` and ID tokens are signed
with a throwaway RSA key the login verifies against.
"""

import asyncio
import base64
import dataclasses
import hashlib
import json
import re
import secrets
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any
from urllib.parse import parse_qs, urlsplit

import httpx
import httpx2
from fastmcp.server.auth.providers.jwt import RSAKeyPair

from veneto_mcp.login import OIDCLogin


@asynccontextmanager
async def running(app: Any) -> AsyncIterator[None]:
    """Run `app`'s lifespan (which `mount` chained the MCP app's into) for the block, in a task
    of its own: test fixtures set up and tear down in different tasks, which anyio's cancel
    scopes inside the MCP session manager don't allow."""
    started, stop = asyncio.Event(), asyncio.Event()

    async def serve() -> None:
        async with app.router.lifespan_context(app):
            started.set()
            await stop.wait()

    task = asyncio.create_task(serve())
    waiter = asyncio.create_task(started.wait())
    await asyncio.wait({task, waiter}, return_when=asyncio.FIRST_COMPLETED)
    if task.done():
        waiter.cancel()
        task.result()  # raises what the lifespan raised
    try:
        yield
    finally:
        stop.set()
        await task


class FakeProvider:
    """The upstream provider's token endpoint. Every code exchange answers with an ID token for
    `next_claims` (issuer and audience from the login unless overridden there)."""

    def __init__(self) -> None:
        self.keys = RSAKeyPair.generate()
        self.next_claims: dict[str, Any] = {}
        #: Override the ID token entirely (e.g. one signed by another key), or drop it (`""`).
        self.next_id_token: str | None = None
        self.exchanges: list[dict[str, str]] = []
        self._login: OIDCLogin | None = None

    def login(self, base: OIDCLogin) -> OIDCLogin:
        self._login = dataclasses.replace(
            base, public_key=self.keys.public_key, transport=httpx2.MockTransport(self._token)
        )
        return self._login

    def id_token(self, claims: dict[str, Any], *, keys: RSAKeyPair | None = None) -> str:
        assert self._login is not None
        claims = {"iss": self._login.issuer, "aud": self._login.client_id} | claims
        return (keys or self.keys).create_token(
            subject=str(claims.pop("sub", "pseudonymous-sub")),
            issuer=claims.pop("iss"),
            audience=claims.pop("aud"),
            expires_in_seconds=int(claims.pop("expires_in", 3600)),
            additional_claims=claims,
        )

    def _token(self, request: httpx2.Request) -> httpx2.Response:
        form = {k: v[0] for k, v in parse_qs(request.content.decode()).items()}
        form["authorization"] = request.headers.get("authorization", "")
        self.exchanges.append(form)
        id_token = self.next_id_token
        if id_token is None:
            id_token = self.id_token(dict(self.next_claims))
        body = {"access_token": "upstream-" + secrets.token_hex(8), "token_type": "Bearer"}
        body |= {"expires_in": 3600, "id_token": id_token} if id_token else {"expires_in": 3600}
        return httpx2.Response(200, json=body)


def _pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(48)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest())
    return verifier, challenge.decode().rstrip("=")


def _form_value(html: str, name: str) -> str:
    match = re.search(rf'name="{name}"\s+value="([^"]+)"', html) or re.search(
        rf'value="([^"]+)"\s+name="{name}"', html
    )
    assert match, f"no {name} in the consent page"
    return match.group(1)


class SignInFlow:
    """One connector being added, as a browser and an MCP client would do it, against an app
    served by `client` (an httpx client with an https base_url, so the Secure cookies stick)."""

    def __init__(
        self,
        client: httpx.AsyncClient,
        *,
        redirect_uri: str = "https://client.test/callback",
        client_name: str = "Test client",
        callback_path: str = "/oauth/callback",
    ) -> None:
        self.client = client
        self.redirect_uri = redirect_uri
        self.client_name = client_name
        self.callback_path = callback_path
        self.client_id: str | None = None
        self._verifier, self._challenge = _pkce()
        self._state = secrets.token_urlsafe(8)
        self.upstream_state: str | None = None

    async def register(self) -> str:
        response = await self.client.post(
            "/register",
            json={
                "redirect_uris": [self.redirect_uri],
                "client_name": self.client_name,
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        assert response.status_code == 201, response.text
        self.client_id = response.json()["client_id"]
        return self.client_id

    async def approve(self) -> httpx.URL:
        """Register (if needed), authorize, approve the consent screen; returns the upstream
        authorize URL the browser is sent to."""
        if self.client_id is None:
            await self.register()
        authorize = await self.client.get(
            "/authorize",
            params={
                "response_type": "code",
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "code_challenge": self._challenge,
                "code_challenge_method": "S256",
                "state": self._state,
            },
        )
        assert authorize.status_code in (302, 307), authorize.text
        consent = await self.client.get(authorize.headers["location"])
        assert consent.status_code == 200, consent.text
        submitted = await self.client.post(
            "/consent",
            data={
                "action": "approve",
                "txn_id": _form_value(consent.text, "txn_id"),
                "csrf_token": _form_value(consent.text, "csrf_token"),
            },
        )
        assert submitted.status_code in (302, 303), submitted.text
        upstream = httpx.URL(submitted.headers["location"])
        self.upstream_state = upstream.params["state"]
        return upstream

    async def callback(self, code: str = "upstream-code") -> httpx.Response:
        """The provider sends the browser back (after the person signed in there)."""
        assert self.upstream_state is not None
        return await self.client.get(
            self.callback_path, params={"code": code, "state": self.upstream_state}
        )

    async def exchange(self, callback: httpx.Response) -> dict[str, Any]:
        """The MCP client trades the code it got on its redirect URI for tokens."""
        assert callback.status_code in (302, 307), callback.text
        location = callback.headers["location"]
        assert location.startswith(self.redirect_uri), location
        query = parse_qs(urlsplit(location).query)
        assert query["state"] == [self._state]
        response = await self.client.post(
            "/token",
            data={
                "grant_type": "authorization_code",
                "code": query["code"][0],
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "code_verifier": self._verifier,
            },
        )
        assert response.status_code == 200, response.text
        return response.json()

    async def refresh(self, refresh_token: str) -> httpx.Response:
        return await self.client.post(
            "/token",
            data={
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "client_id": self.client_id,
            },
        )

    async def connect(self) -> dict[str, Any]:
        """The whole flow; returns the token response (access_token, refresh_token...)."""
        await self.approve()
        return await self.exchange(await self.callback())


async def mcp_post(
    client: httpx.AsyncClient, token: str | None, method: str, params: dict | None = None
) -> httpx.Response:
    """One JSON-RPC request to `/mcp` (stateless: no session to set up first)."""
    headers = {"Accept": "application/json, text/event-stream"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "id": int(time.time() * 1000), "method": method}
    if params is not None:
        body["params"] = params
    return await client.post("/mcp", json=body, headers=headers)


async def mcp_call(
    client: httpx.AsyncClient, token: str, method: str, params: dict | None = None
) -> dict[str, Any]:
    """`mcp_post`, asserting a 200 JSON-RPC result; returns the `result`."""
    response = await mcp_post(client, token, method, params)
    assert response.status_code == 200, response.text
    payload = json.loads(response.text)
    assert "result" in payload, payload
    return payload["result"]


async def call_tool(
    client: httpx.AsyncClient, token: str, tool: str, **arguments: Any
) -> dict[str, Any]:
    """A `tools/call`; returns its result (`isError`, `content`, `structuredContent`)."""
    return await mcp_call(client, token, "tools/call", {"name": tool, "arguments": arguments})
