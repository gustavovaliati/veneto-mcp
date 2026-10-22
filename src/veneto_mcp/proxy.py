"""The OAuth side: FastMCP's OAuthProxy, with the upstream provider demoted to sign-in only.

OAuthProxy gives MCP clients everything they expect (metadata, DCR, CIMD, a consent screen, PKCE,
its own short-lived JWTs and rotating refresh tokens) and keeps per-connector state in the storage
it is given. Out of the box it would also hand the upstream provider's tokens through and
re-validate them on every request, which ties a connector's life to the provider's (Telegram's
expire in an hour and cannot be refreshed). Here instead:

- At the provider's callback, the ID token is verified and turned into an `Identity`, and the
  app's `sign_in(identity, client)` decides: it returns an opaque *grant* (any string the app can
  later resolve, e.g. an API token it just minted), or None to refuse. Refused, unknown and
  unverifiable sign-ins all get the same bare 403 page; no authorization code is issued.
- The grant takes the place of the upstream tokens in OAuthProxy's (encrypted) storage. It never
  leaves the server: clients only ever see FastMCP's JWTs, which point at it.
- Every request, and every refresh, calls the app's `resolve(grant)`; None means 401 (or
  `invalid_grant`) at once. So the app's own rules (an active user, a live token) are the only
  thing keeping a connector alive, and revoking there takes effect on the next request.
"""

import contextvars
import hashlib
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Any

import fastmcp
import httpx2
from authlib.integrations.base_client import OAuthError
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.oauth_proxy import OAuthProxy
from fastmcp.server.auth.oauth_proxy.upstream import AsyncOAuth2Client
from key_value.aio.protocols import AsyncKeyValue
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse

from veneto_mcp.login import Identity, OIDCLogin

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class ConnectorClient:
    """The MCP client a person is connecting (claude.ai, ChatGPT, Claude Code...): its OAuth
    client id (a CIMD URL or a DCR id) and the name it registered with, if any."""

    client_id: str
    name: str | None = None


SignIn = Callable[[Identity, ConnectorClient], Awaitable[str | None]]
Resolve = Callable[[str], Awaitable[Any | None]]

#: The only thing a refused sign-in ever sees, whatever the reason.
DENIED_HTML = (
    '<!doctype html><html lang="pt-BR"><meta charset="utf-8">'
    '<meta name="viewport" content="width=device-width, initial-scale=1">'
    '<title>Acesso negado</title><body style="font-family:system-ui;margin:2rem">'
    "<h1>Acesso negado</h1></body></html>"
)


class SignInRefused(Exception):
    """The upstream sign-in did not produce a grant (stranger, inactive, bad ID token)."""

    def __str__(self) -> str:
        return "sign-in refused"


@dataclass
class _Callback:
    client: ConnectorClient | None
    refused: bool = False


_callback: contextvars.ContextVar[_Callback | None] = contextvars.ContextVar(
    "veneto_mcp_callback", default=None
)


class _GrantVerifier(TokenVerifier):
    """Validates the grant stored behind a FastMCP token by asking the app, every time."""

    def __init__(self, resolve: Resolve) -> None:
        super().__init__()
        self._resolve = resolve

    async def verify_token(self, token: str) -> AccessToken | None:
        if await self._resolve(token) is None:
            return None
        # The FastMCP JWT around it carries the expiry; the grant lives as long as the app says.
        return AccessToken(token=token, client_id="veneto-mcp", scopes=[], expires_at=None)


class _SignInUpstream:
    """What OAuthProxy uses as its upstream token client: the code exchange goes to the
    provider for real and comes back as the app's grant; refreshes never leave the server."""

    def __init__(self, proxy: SignInProxy, real: AsyncOAuth2Client) -> None:
        self._proxy = proxy
        self._real = real
        self.client_id = real.client_id
        self.client_secret = real.client_secret

    async def aclose(self) -> None:
        await self._real.aclose()

    async def fetch_token(self, url: str, **params: Any) -> dict[str, Any]:
        state = _callback.get()
        tokens = await self._real.fetch_token(url=url, **params)
        grant = None
        identity = await self._proxy._login.verify(tokens)
        if identity is not None and state is not None and state.client is not None:
            grant = await self._proxy._sign_in(identity, state.client)
        if not grant:
            if state is not None:
                state.refused = True
            raise SignInRefused
        return self._proxy.grant_tokens(grant)

    async def refresh_token(
        self, url: str, *, refresh_token: str | None = None, **params: Any
    ) -> dict[str, Any]:
        del url, params
        if not refresh_token or await self._proxy._resolve_grant(refresh_token) is None:
            raise OAuthError(error="invalid_grant")
        return self._proxy.grant_tokens(refresh_token)


class SignInProxy(OAuthProxy):
    """OAuthProxy whose upstream only signs people in; the app's grant stands in for the
    upstream tokens (see the module docstring)."""

    def __init__(
        self,
        *,
        login: OIDCLogin,
        sign_in: SignIn,
        resolve: Resolve,
        base_url: str,
        storage: AsyncKeyValue,
        jwt_signing_key: str | bytes,
        access_token_ttl_seconds: int,
        refresh_token_ttl_seconds: int,
    ) -> None:
        if fastmcp.settings.ssrf_trust_proxy:
            # CIMD fetches URLs that clients name; never without the DNS/IP blocklist.
            raise ValueError("veneto-mcp refuses FASTMCP_SSRF_TRUST_PROXY")
        if not jwt_signing_key or len(jwt_signing_key) < 32:
            raise ValueError("jwt_signing_key must be at least 32 characters")
        if isinstance(jwt_signing_key, str):
            # A high-entropy secret needs no stretching (FastMCP would PBKDF2 a str 1M times).
            jwt_signing_key = hashlib.sha256(
                b"veneto-mcp jwt v1\0" + jwt_signing_key.encode()
            ).digest()
        self._login = login
        self._sign_in = sign_in
        self._resolve_grant = resolve
        self._access_ttl = access_token_ttl_seconds
        self._refresh_ttl = refresh_token_ttl_seconds
        super().__init__(
            upstream_authorization_endpoint=login.authorization_endpoint,
            upstream_token_endpoint=login.token_endpoint,
            upstream_client_id=login.client_id,
            upstream_client_secret=login.client_secret,
            token_verifier=_GrantVerifier(resolve),
            base_url=base_url,
            redirect_path=login.redirect_path,
            valid_scopes=list(login.scopes),
            # The provider gets exactly the scopes it needs to identify someone, whatever the
            # MCP client asked for; no RFC 8707 `resource` (OIDC providers don't take it).
            extra_authorize_params={"scope": " ".join(login.scopes)},
            forward_resource=False,
            client_storage=storage,
            jwt_signing_key=jwt_signing_key,
            require_authorization_consent=True,
            enable_cimd=True,
        )

    def grant_tokens(self, grant: str) -> dict[str, Any]:
        """The grant, shaped as the upstream token response OAuthProxy stores (encrypted). No
        `scope`: the FastMCP tokens keep the scopes the client was granted."""
        return {
            "access_token": grant,
            "token_type": "Bearer",
            "expires_in": self._access_ttl,
            "refresh_token": grant,
            "refresh_expires_in": self._refresh_ttl,
        }

    def _create_upstream_oauth_client(self) -> _SignInUpstream:  # type: ignore[override]
        real = AsyncOAuth2Client(
            client_id=self._upstream_client_id,
            client_secret=self._login.client_secret,
            token_endpoint_auth_method=self._token_endpoint_auth_method,
            timeout=15,
        )
        if self._login.transport is not None:
            real._client = httpx2.AsyncClient(timeout=15, transport=self._login.transport)
        return _SignInUpstream(self, real)

    def _prepare_scopes_for_token_exchange(self, scopes: list[str]) -> list[str]:
        del scopes
        return []  # the code exchange carries no scope (RFC 6749 §4.1.3)

    async def _handle_idp_callback(self, request: Request) -> HTMLResponse | RedirectResponse:
        state = _Callback(client=await self._connector_client(request))
        token = _callback.set(state)
        try:
            response = await super()._handle_idp_callback(request)
        finally:
            _callback.reset(token)
        if state.refused:
            return HTMLResponse(DENIED_HTML, status_code=403)
        return response

    async def _connector_client(self, request: Request) -> ConnectorClient | None:
        txn_id = request.query_params.get("state")
        transaction = await self._transaction_store.get(key=txn_id) if txn_id else None
        if transaction is None:
            return None
        client = await self.get_client(transaction.client_id)
        name = getattr(client, "client_name", None) if client is not None else None
        return ConnectorClient(client_id=transaction.client_id, name=name)
