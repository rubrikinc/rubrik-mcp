"""Unit tests for the MCP -> RSC product-identity wiring.

These are mock-based and need no credentials or network: they assert that the
MCP constructs RSCClient with the product identity that drives the SDK
telemetry headers, without ever building a real client.
"""

from types import SimpleNamespace
from unittest.mock import patch

import rubrik.server as server


def test_factory_passes_product_and_version_to_rscclient():
    with patch.object(server, "RSCClient") as mock_client, \
         patch.object(server, "_mcp_version", return_value="1.2.3"), \
         patch.object(server, "_mcp_client_app", return_value=None):
        server._mcp_rsc_client()

    mock_client.assert_called_once_with(product="rubrik-mcp", product_version="1.2.3")


def test_factory_passes_client_app_when_known():
    with patch.object(server, "_MCPRSCClient") as mock_client, \
         patch.object(server, "_mcp_version", return_value="1.2.3"), \
         patch.object(server, "_mcp_client_app", return_value="claude-code/2.1.0"):
        server._mcp_rsc_client()

    mock_client.assert_called_once_with(
        product="rubrik-mcp", product_version="1.2.3", client_app="claude-code/2.1.0"
    )


def _fake_context(name, version, meta=None):
    info = SimpleNamespace(name=name, version=version)
    return SimpleNamespace(
        session=SimpleNamespace(client_params=SimpleNamespace(clientInfo=info)),
        request_context=SimpleNamespace(meta=meta),
    )


def test_client_app_read_from_client_info():
    with patch.object(server.mcp, "get_context", return_value=_fake_context("claude-code", "2.1.0")):
        assert server._mcp_client_app() == "claude-code/2.1.0"


def test_client_app_prefers_per_request_meta():
    # Protocol 2026-07-28 sends clientInfo in each request's _meta (no initialize).
    # Parse a real request _meta so the SDK's handling of the slashed key is covered.
    from mcp.types import RequestParams

    meta = RequestParams.model_validate({"_meta": {
        "io.modelcontextprotocol/clientInfo": {"name": "cursor", "version": "3.0"},
    }}).meta
    with patch.object(server.mcp, "get_context",
                      return_value=_fake_context("old-init-client", "1.0", meta=meta)):
        assert server._mcp_client_app() == "cursor/3.0"


def test_client_app_meta_without_client_info_falls_back_to_initialize():
    from mcp.types import RequestParams

    meta = RequestParams.model_validate({"_meta": {"progressToken": 1}}).meta
    with patch.object(server.mcp, "get_context",
                      return_value=_fake_context("claude-code", "2.1.0", meta=meta)):
        assert server._mcp_client_app() == "claude-code/2.1.0"


def test_client_app_none_when_no_client_info_anywhere():
    ctx = SimpleNamespace(session=SimpleNamespace(client_params=None),
                          request_context=SimpleNamespace(meta=None))
    with patch.object(server.mcp, "get_context", return_value=ctx):
        assert server._mcp_client_app() is None


def test_client_app_is_sanitized_into_a_ua_token():
    # Spaces, parens, and slashes would break User-Agent parsing.
    with patch.object(server.mcp, "get_context",
                      return_value=_fake_context("Visual Studio (Code)", "1.2/3")):
        assert server._mcp_client_app() == "Visual-Studio--Code/1.2-3"


def test_client_app_none_outside_a_request():
    with patch.object(server.mcp, "get_context", side_effect=ValueError("no request")):
        assert server._mcp_client_app() is None


def test_client_app_appended_to_user_agent():
    with patch("rsc.client.load_config", return_value=SimpleNamespace(url="https://x", ca_cert_path=None)), \
         patch("rsc.client.TokenManager") as tm:
        tm.return_value.get_token.return_value = "t"
        with_app = server._MCPRSCClient(product="rubrik-mcp", product_version="1.2.3",
                                        client_app="cursor/1.0")
        without = server._MCPRSCClient(product="rubrik-mcp", product_version="1.2.3")
        ua = with_app.endpoint.base_headers["User-Agent"]
        assert ua.startswith("rubrik-mcp/1.2.3 (") and ua.endswith(") cursor/1.0")
        assert without.endpoint.base_headers["User-Agent"].endswith(")")
        # The attributable SDK headers are untouched.
        assert with_app.endpoint.base_headers["Sdk-Language"] == "rubrik-mcp"
        assert with_app.endpoint.base_headers["Sdk-Version"] == "1.2.3"


def test_product_name_is_bare_rubrik_mcp():
    # The product string must stay bare (no language suffix); runtime details
    # are carried in the User-Agent.
    assert server._MCP_PRODUCT == "rubrik-mcp"


def test_version_falls_back_to_package_version_when_metadata_missing():
    # Even without install metadata the MCP reports its own version — never
    # "unknown" and never the rsc-client version.
    from rubrik import __version__

    with patch.object(server, "_pkg_version", side_effect=server.PackageNotFoundError):
        assert server._mcp_version() == __version__


def test_call_sites_use_the_factory_not_raw_rscclient():
    # Every live API path should route through the factory so the headers are
    # always sent. Guards against a new RSCClient() call site slipping in.
    import inspect

    src = inspect.getsource(server)
    # The only legitimate bare "client = RSCClient()" lives in a docstring
    # example; real code must call the factory.
    code_lines = [
        ln for ln in src.splitlines()
        if "client = RSCClient()" in ln and not ln.lstrip().startswith('"')
    ]
    assert code_lines == [], f"raw RSCClient() call sites found: {code_lines}"
