"""A remote, OAuth-protected MCP endpoint for a FastAPI app (README.md)."""

from veneto_mcp.login import Identity, OIDCLogin, google, telegram
from veneto_mcp.proxy import ConnectorClient
from veneto_mcp.server import DEFAULT_REDIRECT_URIS, DENIED, RemoteMCP, build_mcp, current_grant
from veneto_mcp.storage import SQLStore, encrypted, kv_table

__all__ = [
    "DEFAULT_REDIRECT_URIS",
    "DENIED",
    "ConnectorClient",
    "Identity",
    "OIDCLogin",
    "RemoteMCP",
    "SQLStore",
    "build_mcp",
    "current_grant",
    "encrypted",
    "google",
    "kv_table",
    "telegram",
]
