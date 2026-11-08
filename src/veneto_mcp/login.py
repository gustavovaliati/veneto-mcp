"""Upstream sign-in: an OIDC provider that only proves who the person is, once per connector.

`OIDCLogin` holds what the proxy needs to send someone to the provider and to verify the ID token
that comes back; `identity` turns the verified claims into an `Identity`, or None to refuse.
`telegram()` and `google()` are presets; any other OIDC provider is one more `OIDCLogin`.
"""

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import cached_property
from typing import Any

import httpx2
from fastmcp.server.auth.providers.jwt import JWTVerifier

#: Leeway between our clock and the provider's, in seconds.
CLOCK_SKEW_SECONDS = 60
#: An ID token issued longer ago than this is refused, whatever its `exp` says. It arrives over
#: the back channel seconds after it is issued, so this only bounds a token replayed later.
MAX_ID_TOKEN_AGE_SECONDS = 600


@dataclass(frozen=True)
class Identity:
    """Who signed in, as the upstream provider vouched for it (signature, issuer, audience,
    expiry and issue time of its ID token checked). `subject` is the provider's stable id for
    the person."""

    provider: str
    subject: str
    name: str | None = None
    username: str | None = None
    claims: dict[str, Any] = field(default_factory=dict, repr=False)


@dataclass(frozen=True)
class OIDCLogin:
    """An OIDC provider used only to sign in (authorization code + PKCE, ID token verified
    server-side; no userinfo call, no upstream refresh)."""

    provider: str
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    client_id: str
    client_secret: str = field(repr=False)
    #: Requested upstream on every sign-in, whatever the MCP client asks for.
    scopes: tuple[str, ...]
    #: Verified claims -> Identity, or None when the claims don't identify anyone usable.
    identity: Callable[[dict[str, Any]], Identity | None]
    jwks_uri: str | None = None
    #: Verify ID tokens against this PEM key instead of `jwks_uri` (tests).
    public_key: str | None = field(default=None, repr=False)
    algorithm: str = "RS256"
    #: The token endpoint's HTTP transport (tests: an `httpx2.MockTransport`).
    transport: httpx2.AsyncBaseTransport | None = field(default=None, repr=False)
    #: Where the provider sends the browser back; register `<base_url><redirect_path>` with it.
    redirect_path: str = "/oauth/callback"

    def __post_init__(self) -> None:
        if not self.client_id or not self.client_secret:
            raise ValueError(f"{self.provider}: client id and secret are required")
        if not (self.jwks_uri or self.public_key):
            raise ValueError(f"{self.provider}: jwks_uri or public_key is required")
        if "openid" not in self.scopes:
            raise ValueError(f"{self.provider}: the openid scope is required")

    def id_token_verifier(self) -> JWTVerifier:
        """One verifier per login, so the provider's JWKS is fetched once and cached, not on
        every sign-in."""
        return self._verifier

    @cached_property
    def _verifier(self) -> JWTVerifier:
        return JWTVerifier(
            jwks_uri=None if self.public_key else self.jwks_uri,
            public_key=self.public_key,
            issuer=self.issuer,
            audience=self.client_id,
            algorithm=self.algorithm,
        )

    async def verify(self, tokens: dict[str, Any]) -> Identity | None:
        """The Identity in a token response's ID token, or None if it doesn't verify."""
        id_token = tokens.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            return None
        verified = await self.id_token_verifier().verify_token(id_token)
        if verified is None or not verified.claims:
            return None
        claims = dict(verified.claims)
        if not _fresh(claims, time.time()):
            return None
        return self.identity(claims)


def _fresh(claims: dict[str, Any], now: float) -> bool:
    """`exp` and `iat` are both required (the verifier checks `exp` only when present): not
    expired, not issued in the future, not issued more than MAX_ID_TOKEN_AGE_SECONDS ago."""
    exp, iat = claims.get("exp"), claims.get("iat")
    if any(isinstance(v, bool) or not isinstance(v, int | float) for v in (exp, iat)):
        return False
    return (
        exp > now - CLOCK_SKEW_SECONDS
        and iat <= now + CLOCK_SKEW_SECONDS
        and iat >= now - MAX_ID_TOKEN_AGE_SECONDS - CLOCK_SKEW_SECONDS
    )


TELEGRAM_ISSUER = "https://oauth.telegram.org"


def _telegram_identity(claims: dict[str, Any]) -> Identity | None:
    # `sub` is a pseudonymous id; the Telegram user id (what bots and initData know) is the `id`
    # claim, which comes only with the `profile` scope (core.telegram.org/bots/telegram-login).
    user_id = claims.get("id")
    if isinstance(user_id, bool) or not isinstance(user_id, int | str):
        return None
    try:
        user_id = int(user_id)
    except ValueError:
        return None
    if user_id <= 0:
        return None
    return Identity(
        provider="telegram",
        subject=str(user_id),
        name=claims.get("name"),
        username=claims.get("preferred_username"),
        claims=claims,
    )


def telegram(client_id: str, client_secret: str, **overrides: Any) -> OIDCLogin:
    """Log in with Telegram (BotFather > the bot > Login Widget: Client ID and Secret; add
    `<base_url>/oauth/callback` to its Allowed URLs). `Identity.subject` is the Telegram user id."""
    settings: dict[str, Any] = {
        "provider": "telegram",
        "issuer": TELEGRAM_ISSUER,
        "authorization_endpoint": f"{TELEGRAM_ISSUER}/auth",
        "token_endpoint": f"{TELEGRAM_ISSUER}/token",
        "jwks_uri": f"{TELEGRAM_ISSUER}/.well-known/jwks.json",
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": ("openid", "profile"),
        "identity": _telegram_identity,
    }
    return OIDCLogin(**(settings | overrides))


def _google_identity(claims: dict[str, Any]) -> Identity | None:
    subject = claims.get("sub")
    if not isinstance(subject, str) or not subject:
        return None
    email = claims.get("email") if claims.get("email_verified") is True else None
    return Identity(
        provider="google", subject=subject, name=claims.get("name"), username=email, claims=claims
    )


def google(client_id: str, client_secret: str, **overrides: Any) -> OIDCLogin:
    """Log in with Google. `Identity.subject` is Google's `sub`; `username` is the e-mail, only
    when Google says it is verified."""
    settings: dict[str, Any] = {
        "provider": "google",
        "issuer": "https://accounts.google.com",
        "authorization_endpoint": "https://accounts.google.com/o/oauth2/v2/auth",
        "token_endpoint": "https://oauth2.googleapis.com/token",
        "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
        "client_id": client_id,
        "client_secret": client_secret,
        "scopes": ("openid", "email", "profile"),
        "identity": _google_identity,
    }
    return OIDCLogin(**(settings | overrides))
