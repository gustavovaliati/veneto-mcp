"""The sign-in flow and the token checks, at the HTTP seam."""

import json

import pytest
from fastmcp.exceptions import ToolError
from fastmcp.server.auth import AccessToken
from fastmcp.server.auth.providers.jwt import RSAKeyPair
from sqlalchemy import select

from tests.conftest import ALICE, BASE_URL, BOB, STRANGER
from veneto_mcp import build_mcp, telegram
from veneto_mcp.proxy import DENIED_HTML
from veneto_mcp.testing import SignInFlow, call_tool, mcp_call, mcp_post


async def _connect(client, provider, user=ALICE, **claims):
    provider.next_claims = {"id": user, "name": "Alice"} | claims
    return await SignInFlow(client).connect()


async def test_metadata_advertises_the_endpoints_dcr_and_cimd(client):
    server = (await client.get("/.well-known/oauth-authorization-server")).json()
    assert server["issuer"].rstrip("/") == BASE_URL
    assert server["authorization_endpoint"] == f"{BASE_URL}/authorize"
    assert server["token_endpoint"] == f"{BASE_URL}/token"
    assert server["registration_endpoint"] == f"{BASE_URL}/register"
    assert server["client_id_metadata_document_supported"] is True
    assert server["code_challenge_methods_supported"] == ["S256"]
    resource = (await client.get("/.well-known/oauth-protected-resource/mcp")).json()
    assert resource["resource"] == f"{BASE_URL}/mcp"
    assert [s.rstrip("/") for s in resource["authorization_servers"]] == [BASE_URL]


async def test_without_a_token_mcp_is_401_pointing_at_the_metadata(client):
    response = await mcp_post(client, None, "tools/list")
    assert response.status_code == 401
    challenge = response.headers["www-authenticate"]
    assert challenge.startswith("Bearer")
    assert f'resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource/mcp"' in challenge
    garbage = await mcp_post(client, "not-a-token", "tools/list")
    assert garbage.status_code == 401


async def test_an_allowed_user_signs_in_once_and_calls_tools(client, provider, users):
    tokens = await _connect(client, provider)
    assert set(tokens) >= {"access_token", "refresh_token", "expires_in"}
    assert tokens["expires_in"] == 3600
    # Clients only ever hold the proxy's JWTs, never the app's grant.
    assert not any(grant in json.dumps(tokens) for grant in users.grants)

    tools = await mcp_call(client, tokens["access_token"], "tools/list")
    assert [t["name"] for t in tools["tools"]] == ["whoami"]
    result = await call_tool(client, tokens["access_token"], "whoami")
    assert result["structuredContent"] == {"user": ALICE}

    identity, connector = users.sign_ins[0]
    assert (identity.provider, identity.subject, identity.name) == ("telegram", "111", "Alice")
    assert connector.name == "Test client"
    assert connector.client_id


async def test_upstream_is_asked_for_openid_profile_with_pkce_and_basic_auth(client, provider):
    flow = SignInFlow(client)
    upstream = await flow.approve()
    assert str(upstream).startswith("https://oauth.telegram.org/auth?")
    assert upstream.params["client_id"] == "424242"
    assert upstream.params["scope"] == "openid profile"
    assert upstream.params["redirect_uri"] == f"{BASE_URL}/oauth/callback"
    assert upstream.params["code_challenge_method"] == "S256"
    assert "resource" not in upstream.params
    provider.next_claims = {"id": ALICE}
    await flow.exchange(await flow.callback("the-code"))
    (exchange,) = provider.exchanges
    assert exchange["code"] == "the-code"
    assert exchange["code_verifier"]
    assert exchange["redirect_uri"] == f"{BASE_URL}/oauth/callback"
    assert exchange["authorization"].startswith("Basic ")
    assert "scope" not in exchange


@pytest.mark.parametrize(
    "case",
    ["stranger", "no id claim", "foreign signature", "wrong audience", "expired", "no id token"],
)
async def test_every_refused_sign_in_gets_the_same_bare_403(client, provider, users, case):
    claims = {"id": ALICE}
    if case == "stranger":
        claims = {"id": STRANGER}
    elif case == "no id claim":
        claims = {"sub": str(ALICE)}  # `sub` is pseudonymous on Telegram: never trusted as the id
    elif case == "foreign signature":
        provider.next_id_token = provider.id_token(claims, keys=RSAKeyPair.generate())
    elif case == "wrong audience":
        provider.next_id_token = provider.id_token(claims | {"aud": "another-bot"})
    elif case == "expired":
        provider.next_id_token = provider.id_token(claims | {"expires_in": -60})
    elif case == "no id token":
        provider.next_id_token = ""
    provider.next_claims = claims
    flow = SignInFlow(client)
    await flow.approve()
    response = await flow.callback()
    assert response.status_code == 403
    assert response.text == DENIED_HTML
    assert "location" not in response.headers
    assert not users.grants
    assert len(users.sign_ins) == (1 if case == "stranger" else 0)


async def test_a_deactivated_user_is_cut_off_at_the_next_request(client, provider, users):
    tokens = await _connect(client, provider)
    assert (await mcp_post(client, tokens["access_token"], "tools/list")).status_code == 200
    users.active.discard(ALICE)
    assert (await mcp_post(client, tokens["access_token"], "tools/list")).status_code == 401
    refreshed = await SignInFlow(client).refresh(tokens["refresh_token"])
    assert refreshed.status_code in (400, 401)


async def test_refresh_never_calls_upstream_and_rotates(client, provider):
    flow = SignInFlow(client)
    provider.next_claims = {"id": BOB}
    tokens = await flow.connect()
    refreshed = await flow.refresh(tokens["refresh_token"])
    assert refreshed.status_code == 200, refreshed.text
    new = refreshed.json()
    assert new["refresh_token"] != tokens["refresh_token"]
    assert len(provider.exchanges) == 1  # the sign-in only
    result = await call_tool(client, new["access_token"], "whoami")
    assert result["structuredContent"] == {"user": BOB}
    assert (await flow.refresh(tokens["refresh_token"])).status_code in (400, 401)


async def test_a_tool_rechecks_the_principal(client, provider, users, remote, monkeypatch):
    await _connect(client, provider)
    (grant,) = users.grants
    # A tool call whose request already passed the transport check (the token is in context).
    monkeypatch.setattr(
        "veneto_mcp.server.get_access_token",
        lambda: AccessToken(token=grant, client_id="c", scopes=[]),
    )
    assert await remote.principal() == ALICE
    users.active.discard(ALICE)
    with pytest.raises(ToolError, match="Acesso negado"):
        await remote.principal()
    monkeypatch.setattr("veneto_mcp.server.get_access_token", lambda: None)
    with pytest.raises(ToolError, match="Acesso negado"):
        await remote.principal()


async def test_the_oauth_state_is_encrypted_at_rest(client, provider, users, db):
    tokens = await _connect(client, provider)
    async with db.engine.connect() as conn:
        rows = (await conn.execute(select(db.table.c.value))).scalars().all()
    assert rows
    dump = "\n".join(rows)
    (grant,) = users.grants
    assert grant not in dump
    assert tokens["refresh_token"] not in dump
    assert "Test client" not in dump


async def test_the_app_keeps_its_routes_404s_and_lifespan(client, app):
    assert (await client.get("/api/hello")).json() == {"hello": "world"}
    missing = await client.get("/api/nope")
    assert (missing.status_code, missing.json()) == (404, {"detail": "Not Found"})
    assert app.state.started == [True]


def test_mount_adds_exactly_the_oauth_and_mcp_paths(remote):
    assert sorted(remote.paths) == sorted(
        [
            "/.well-known/oauth-authorization-server",
            "/.well-known/oauth-protected-resource/mcp",
            "/authorize",
            "/token",
            "/register",
            "/consent",
            "/oauth/callback",
            "/mcp",
        ]
    )


def _build(db, **overrides):
    settings = {
        "instructions": "x",
        "base_url": BASE_URL,
        "login": telegram("1", "secret", public_key="k"),
        "sign_in": None,
        "resolve": None,
        "storage": db.store(),
        "jwt_signing_key": "j" * 40,
    } | overrides
    return build_mcp("x", **settings)


def test_refuses_a_short_signing_key(db):
    with pytest.raises(ValueError, match="jwt_signing_key"):
        _build(db, jwt_signing_key="short")


def test_refuses_plain_http(db):
    with pytest.raises(ValueError, match="https"):
        _build(db, base_url="http://mcp.test")


def test_refuses_to_run_cimd_without_the_ssrf_blocklist(db, monkeypatch):
    import fastmcp

    monkeypatch.setattr(fastmcp.settings, "ssrf_trust_proxy", True)
    with pytest.raises(ValueError, match="SSRF"):
        _build(db)


async def test_a_callback_without_a_pending_sign_in_is_refused_too(client):
    response = await client.get("/oauth/callback", params={"code": "c", "state": "forged"})
    assert (response.status_code, response.text) == (403, DENIED_HTML)


async def test_an_app_sign_in_that_raises_is_a_bare_refusal(client, provider, users, caplog):
    users.broken = True
    provider.next_claims = {"id": ALICE}
    flow = SignInFlow(client)
    await flow.approve()
    response = await flow.callback()
    assert (response.status_code, response.text) == (403, DENIED_HTML)
    assert "connector: Alice" not in caplog.text


@pytest.mark.parametrize(
    "redirect_uri",
    ["https://evil.test/callback", "https://claude.ai.evil.test/api/mcp/auth_callback"],
)
async def test_a_client_with_a_foreign_redirect_uri_cannot_register(client, redirect_uri):
    response = await client.post(
        "/register",
        json={"redirect_uris": [redirect_uri], "token_endpoint_auth_method": "none"},
    )
    assert response.status_code == 400


async def test_claude_ai_and_loopback_clients_can_register(client):
    for redirect_uri in ("https://claude.ai/api/mcp/auth_callback", "http://127.0.0.1:5000/cb"):
        flow = SignInFlow(client, redirect_uri=redirect_uri)
        assert await flow.register()
