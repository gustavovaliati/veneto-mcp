"""The SQL key-value store and the provider presets."""

import asyncio

import pytest

from veneto_mcp import encrypted, google, telegram
from veneto_mcp.login import OIDCLogin
from veneto_mcp.storage import fernet_key


async def test_put_get_delete_and_collections(db):
    store = db.store()
    await store.put("k", {"a": 1}, collection="one")
    await store.put("k", {"b": 2}, collection="two")
    assert await store.get("k", collection="one") == {"a": 1}
    await store.put("k", {"a": 3}, collection="one")
    assert await store.get("k", collection="one") == {"a": 3}
    assert await store.delete("k", collection="one") is True
    assert await store.delete("k", collection="one") is False
    assert await store.get("k", collection="one") is None
    assert await store.get("k", collection="two") == {"b": 2}


async def test_ttl_expires_and_purges(db):
    store = db.store()
    await store.put("short", {"x": 1}, ttl=0.05)
    await store.put("long", {"x": 2}, ttl=3600)
    value, ttl = await store.ttl("long")
    assert value == {"x": 2} and 3500 < ttl <= 3600
    await asyncio.sleep(0.1)
    assert await store.get("short") is None
    assert await store.purge_expired() == 1
    assert await store.get("long") == {"x": 2}


async def test_encrypted_values_dont_survive_a_new_secret(db):
    raw = db.store()
    await encrypted(raw, "a" * 32).put("k", {"secret": "value"})
    stored = await raw.get("k")
    assert "value" not in str(stored)
    assert await encrypted(raw, "a" * 32).get("k") == {"secret": "value"}
    assert await encrypted(raw, "b" * 32).get("k") is None


def test_the_storage_secret_must_be_long():
    with pytest.raises(ValueError):
        fernet_key("short")


def test_telegram_maps_the_id_claim_never_sub():
    login = telegram("1", "s")
    identity = login.identity({"sub": "9999999999999", "id": 987654321, "name": "Ana"})
    assert (identity.subject, identity.name) == ("987654321", "Ana")
    assert login.identity({"sub": "987654321"}) is None
    assert login.identity({"id": True}) is None
    assert login.identity({"id": "abc"}) is None
    assert login.identity({"id": -5}) is None
    assert login.scopes == ("openid", "profile")


def test_google_trusts_only_a_verified_email():
    login = google("1", "s")
    assert login.identity({"sub": "g1", "email": "a@x", "email_verified": True}).username == "a@x"
    assert login.identity({"sub": "g1", "email": "a@x", "email_verified": False}).username is None


def test_a_login_needs_credentials_keys_and_openid():
    base = telegram("1", "s")
    for overrides in ({"client_secret": ""}, {"jwks_uri": None}, {"scopes": ("profile",)}):
        with pytest.raises(ValueError):
            OIDCLogin(**(vars(base) | overrides))


def test_the_client_secret_is_not_in_the_repr():
    assert "s3cr3t" not in repr(telegram("1", "s3cr3t"))
