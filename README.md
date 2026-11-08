# veneto-mcp

A remote, OAuth-protected MCP endpoint for a FastAPI app, so people can add it as a custom connector
in claude.ai (web, desktop, mobile), ChatGPT developer mode or Claude Code. They sign in **once per
connector** with an OIDC provider (Telegram, Google, ...); **your app** decides who gets in and keeps
deciding on every request.

Built on [FastMCP](https://gofastmcp.com)'s `OAuthProxy` (pinned): clients get OAuth 2.1 metadata,
Dynamic Client Registration, Client ID Metadata Documents (claude.ai's recommended identity), a consent
screen, PKCE, short-lived JWTs and rotating refresh tokens. The upstream provider is used only to prove
who the person is.

## Adopting it

```python
from veneto_mcp import SQLStore, build_mcp, encrypted, kv_table, telegram

kv = kv_table(Base.metadata)  # one table, created by your Alembic migration

async def sign_in(identity, client):  # once, after Telegram vouched for identity.subject
    user = await find_active_user(telegram_id=int(identity.subject))
    return await mint_token_for(user, f"connector {client.name}") if user else None

async def resolve(grant):  # every request and every refresh; None cuts the connector off
    return await active_user_for_token(grant)

remote = build_mcp(
    "myapp", instructions="What these tools do.", base_url="https://myapp.example.com",
    login=telegram(settings.oidc_client_id, settings.oidc_client_secret),
    sign_in=sign_in, resolve=resolve, jwt_signing_key=settings.mcp_jwt_signing_key,
    storage=encrypted(SQLStore(get_engine(), kv), settings.mcp_storage_secret),
)

@remote.server.tool()
async def list_things() -> list[dict]:
    """Shown to the model."""
    user = await remote.principal()  # re-resolved from the grant; ToolError if gone
    return await things_for(user)

remote.mount(app)  # /mcp + the OAuth routes on your FastAPI app, lifespan chained
```

The connector URL is then `https://myapp.example.com/mcp`.

## The contract

- `sign_in(identity, client) -> grant | None`. `identity` (`provider`, `subject`, `name`, `username`,
  `claims`) has been verified (ID token signature, issuer, audience, expiry). Return any string you can
  resolve later (an API token you mint for this connector is a good fit: you can then list and revoke it
  like any other), or None. Strangers, inactive users and bad ID tokens all get the same bare
  "Acesso negado" page and no authorization code.
- `resolve(grant) -> principal | None`, on **every** MCP request and token refresh. None means a 401
  (or `invalid_grant`) right away: deactivating the user or revoking the grant in your app is the
  revocation. The grant never leaves the server; clients only hold FastMCP's JWTs pointing at it.
- Tools: `await remote.principal()` (resolved again), or `current_grant()` for the raw grant (e.g. to
  call your own HTTP API in process with it, so every route's checks apply unchanged).

## Which clients may connect

Only clients whose redirect URI matches `allowed_redirect_uris` may register or sign in. The default is
claude.ai's and ChatGPT's callbacks plus loopback (Claude Code, MCP Inspector). Without that list, anyone
could register a redirect URI of their own and phish a user into approving it on the consent screen.

## Paths `mount` adds

`/mcp`, `/.well-known/oauth-authorization-server`, `/.well-known/oauth-protected-resource/mcp`,
`/authorize`, `/token`, `/register`, `/consent` and the provider's callback `/oauth/callback`. Proxy all
of them to the app (the SPA must not own them). `/mcp` answers stateless JSON (no sessions to lose on a
restart, nothing to stream), but turn proxy buffering off for it anyway.

## Providers

- `telegram(client_id, client_secret)`: BotFather > your bot > Login Widget gives the Client ID and
  Secret; add `<base_url>/oauth/callback` to its Allowed URLs. Scopes `openid profile`; `subject` is the
  Telegram user id (the `id` claim; Telegram's `sub` is pseudonymous and never used). Telegram's tokens
  last an hour and can't be refreshed; that doesn't matter here, since the connector lives on your grant.
- `google(client_id, client_secret)`: `subject` is Google's `sub`, `username` the e-mail when verified.
- Anything else OIDC: `OIDCLogin(provider=..., issuer=..., authorization_endpoint=..., token_endpoint=...,
  jwks_uri=..., client_id=..., client_secret=..., scopes=("openid", ...), identity=claims_to_identity)`.

## Secrets and storage

- `jwt_signing_key` (>= 32 chars) signs the tokens clients hold. Rotating it disconnects every connector.
- `encrypted(store, secret)` (>= 32 chars) Fernet-encrypts every stored value (client registrations,
  grants, codes). Rotating it makes the old state unreadable: connectors sign in again.
- `SQLStore(engine, kv_table(metadata))` works on Postgres and SQLite; expired rows are purged every 200
  writes (`await store.purge_expired()` to do it yourself).
- CIMD fetches client-named URLs through FastMCP's SSRF guard (DNS-pinned, private ranges blocked);
  `build_mcp` refuses to start with `FASTMCP_SSRF_TRUST_PROXY` set.

## Security notes for adopters

- **Rate-limit the OAuth routes at your reverse proxy** (`/register`, `/authorize`, `/consent`,
  `/token`, the provider's callback). Dynamic Client Registration is open to anyone, by design.
  A registration that no sign-in completes with is deleted after an hour; a used one lives as
  long as its refresh token could, renewed on every refresh.
- **Cap the request body size there too** (for example `client_max_body_size 16k` on
  `/register`): a rate limit counts requests, not bytes, and a registration's `client_name`
  and redirect URIs are stored as sent.
- **Use `encrypted(...)` storage.** `build_mcp` accepts any store, and a plain one keeps your
  grants (API tokens, say) in clear text.
- **A grant `sign_in` returns may never be used.** If the person abandons the flow, or the
  client never redeems its code (5 minutes), nothing points at the grant any more. Mint grants
  that expire, or replace the previous grant of the same client, as you would any token.
- **`ConnectorClient.name` is chosen by whoever registered the client.** Treat it as untrusted
  text: escape it before showing it, and never use it to decide anything.
- **Keep the `fastmcp` logger above DEBUG in production.** At DEBUG, FastMCP logs full
  authorization codes.
- **Never configure an upstream revocation endpoint.** The grant stands in for the upstream
  tokens, so FastMCP would send your app's grant (an API token, say) to the provider.
  Disconnecting a connector means revoking its grant in your app: `resolve` then returns None.
- **The storage protects confidentiality, not integrity.** Values are Fernet-encrypted, but a
  ciphertext is not bound to the collection and key it was stored under, keys are stored in
  plain text, and an unencrypted value is read back as is. Someone who can write to the table
  (but holds no app secret) could move one person's stored grant under the key of their own
  token. Keep the table as protected as the rest of your database.
- **One-time use is FastMCP's.** Redeeming an authorization code and rotating a refresh token
  are a read then a delete, so two simultaneous requests could both succeed; reusing an old
  refresh token is refused but does not revoke the newer one.
- ID tokens are checked for signature, issuer, audience, `exp` and `iat` (both required; issued
  at most ten minutes ago, with a minute of clock skew).

## Testing your app

`veneto_mcp.testing` (extra `testing`) has a `FakeProvider` (an ID-token-signing token endpoint over
`httpx2.MockTransport`; `provider.login(telegram("1", "secret"))`), `SignInFlow(client).connect()` (DCR,
consent, callback, code exchange, as a browser and a client would), `running(app)` (the lifespan, in a
task of its own) and `mcp_call` / `call_tool`. No network involved. See `tests/`.

## Development

```bash
uv sync --extra testing
uv run pytest -q
uv run ruff check . && uv run ruff format --check .
```

Releases are git tags (`v0.1.1`); apps depend on a tag:
`veneto-mcp = { git = "https://github.com/gustavovaliati/veneto-mcp", tag = "v0.1.1" }`.
