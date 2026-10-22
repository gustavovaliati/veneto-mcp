"""`build_mcp`: a FastMCP server behind the sign-in proxy, and how to mount it in a FastAPI app."""

from collections.abc import AsyncIterator
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from dataclasses import dataclass, field
from typing import Any

from fastmcp import FastMCP
from fastmcp.exceptions import ToolError
from fastmcp.server.dependencies import get_access_token
from key_value.aio.protocols import AsyncKeyValue
from starlette.applications import Starlette
from starlette.routing import Route

from veneto_mcp.login import OIDCLogin
from veneto_mcp.proxy import Resolve, SignIn, SignInProxy

#: What a tool says when the caller has no (more) access. Same for every reason.
DENIED = "Acesso negado"


def current_grant() -> str:
    """The grant behind the current request's token (what `sign_in` returned). Only inside a
    tool call; raises ToolError when there is none."""
    token = get_access_token()
    if token is None or not token.token:
        raise ToolError(DENIED)
    return token.token


@dataclass
class RemoteMCP:
    """A built server: register tools on `.server`, then `.mount(app)`."""

    server: FastMCP
    path: str
    _resolve: Resolve = field(repr=False)
    _http_app: Starlette | None = field(default=None, repr=False)

    async def principal(self) -> Any:
        """The app's principal for the current tool call, resolved again from its grant (so a
        user deactivated mid-session is refused here too). ToolError when it no longer resolves."""
        principal = await self._resolve(current_grant())
        if principal is None:
            raise ToolError(DENIED)
        return principal

    def http_app(self) -> Starlette:
        if self._http_app is None:
            # Stateless JSON: no in-memory sessions to lose on a restart, nothing to stream
            # through proxies (MCP clients must accept a JSON response).
            self._http_app = self.server.http_app(
                path=self.path, stateless_http=True, json_response=True
            )
        return self._http_app

    def lifespan(self) -> AbstractAsyncContextManager[None]:
        """The MCP app's lifespan alone (its session manager); `mount` chains it for you."""
        app = self.http_app()
        return app.router.lifespan_context(app)

    def mount(self, app: Starlette) -> None:
        """Serve the MCP endpoint and the OAuth routes from `app`, at the paths the metadata
        advertises (`/mcp`, `/.well-known/oauth-*`, `/authorize`, `/token`, `/register`,
        `/consent`, the provider's callback). Each is a route of its own on `app`, so the rest of
        the app (its 404s, its other routes) is untouched; `app`'s lifespan now also runs the
        MCP app's (FastAPI never runs a sub-app's)."""
        mcp_app = self.http_app()
        for route in mcp_app.routes:
            if not isinstance(route, Route):
                raise TypeError(f"unexpected MCP route {route!r}")
            # An ASGI app as the endpoint: the MCP app routes (and authenticates) the request.
            app.router.routes.append(Route(route.path, endpoint=mcp_app, include_in_schema=False))
        app_lifespan = app.router.lifespan_context

        @asynccontextmanager
        async def lifespan(asgi_app: Any) -> AsyncIterator[Any]:
            async with self.lifespan(), app_lifespan(asgi_app) as state:
                yield state

        app.router.lifespan_context = lifespan

    @property
    def paths(self) -> list[str]:
        """Every path `mount` adds."""
        return [route.path for route in self.http_app().routes if isinstance(route, Route)]


def build_mcp(
    name: str,
    *,
    instructions: str,
    base_url: str,
    login: OIDCLogin,
    sign_in: SignIn,
    resolve: Resolve,
    storage: AsyncKeyValue,
    jwt_signing_key: str,
    path: str = "/mcp",
    access_token_ttl_seconds: int = 3600,
    refresh_token_ttl_seconds: int = 90 * 24 * 3600,
) -> RemoteMCP:
    """A remote MCP server at `<base_url><path>`, protected by OAuth 2.1 (metadata, DCR and
    CIMD for clients; consent screen; PKCE), where people sign in with `login` once per
    connector and the app decides who gets in:

    - `sign_in(identity, client)`: called once, after the provider vouched for `identity`.
      Return a grant (an opaque string you can resolve later, e.g. an API token you mint for
      this connector) or None to refuse (the person sees a bare "Acesso negado").
    - `resolve(grant)`: called on every request and every token refresh. Return your principal
      (e.g. the active user), or None to cut the connector off at once.

    `storage` holds the OAuth state: use `encrypted(SQLStore(...), secret)` in production.
    `jwt_signing_key` (>= 32 chars) signs the tokens clients hold; rotating it signs everyone
    out of their connectors. Access tokens live `access_token_ttl_seconds`; refresh tokens
    rotate on use and lapse after `refresh_token_ttl_seconds` without one.
    """
    if not base_url.startswith("https://") and "://localhost" not in base_url:
        raise ValueError("base_url must be https (or localhost)")
    auth = SignInProxy(
        login=login,
        sign_in=sign_in,
        resolve=resolve,
        base_url=base_url.rstrip("/"),
        storage=storage,
        jwt_signing_key=jwt_signing_key,
        access_token_ttl_seconds=access_token_ttl_seconds,
        refresh_token_ttl_seconds=refresh_token_ttl_seconds,
    )
    server = FastMCP(name, instructions=instructions, auth=auth)
    return RemoteMCP(server=server, path=path, _resolve=resolve)
