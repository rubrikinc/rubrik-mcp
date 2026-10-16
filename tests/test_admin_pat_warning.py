"""
Unit tests for the administrator personal access token warning — no RSC
credentials required (mock-based).
"""

from unittest.mock import MagicMock, patch

import pytest

import rubrik.server as server

ADMIN = "00000000-0000-0000-0000-000000000000"
OWNER = "00000000-0000-0000-0000-000000000009"
READONLY_ADMIN = "00000000-0000-0000-0000-000000000017"
CUSTOM = "4f1c2b7e-0d6a-4c39-9b8e-2a7d5e1f3c90"


@pytest.fixture(autouse=True)
def _reset_state():
    original_instructions = server.mcp._mcp_server.instructions
    server._pending_admin_pat_warning = None
    yield
    server._pending_admin_pat_warning = None
    server.mcp._mcp_server.instructions = original_instructions


def _user(roles, owner=False):
    return {"isAccountOwner": owner, "roles": roles}


def _run_check(token_uri, current_user):
    client = MagicMock()
    client.execute.return_value = {"data": {"currentUser": current_user}}
    config = MagicMock(token_uri=token_uri)
    with patch("rsc.config.load_config", return_value=config), \
         patch.object(server, "_mcp_rsc_client", return_value=client):
        server._check_admin_pat()
    return client


PAT_URI = "https://example.my.rubrik.com/api/pat_login"
SA_URI = "https://example.my.rubrik.com/api/client_token"


@pytest.mark.parametrize("user", [
    _user([{"id": ADMIN, "isOrgAdmin": False}]),
    _user([{"id": OWNER, "isOrgAdmin": False}]),
    _user([{"id": READONLY_ADMIN, "isOrgAdmin": False}]),
    _user([{"id": CUSTOM, "isOrgAdmin": True}]),
    _user([{"id": CUSTOM, "isOrgAdmin": False}], owner=True),
])
def test_admin_pat_sets_warning(user):
    _run_check(PAT_URI, user)
    assert server._pending_admin_pat_warning == server._ADMIN_PAT_WARNING
    assert server._ADMIN_PAT_WARNING in server.mcp._mcp_server.instructions


@pytest.mark.parametrize("user", [
    _user([{"id": CUSTOM, "isOrgAdmin": False}]),
    _user([]),
    {},
])
def test_non_admin_pat_no_warning(user):
    original = server.mcp._mcp_server.instructions
    _run_check(PAT_URI, user)
    assert server._pending_admin_pat_warning is None
    assert server.mcp._mcp_server.instructions == original


def test_service_account_skips_query():
    client = _run_check(SA_URI, _user([{"id": ADMIN, "isOrgAdmin": False}]))
    client.execute.assert_not_called()
    assert server._pending_admin_pat_warning is None


def test_pat_uri_with_trailing_slash_is_detected():
    _run_check(PAT_URI + "/", _user([{"id": ADMIN, "isOrgAdmin": False}]))
    assert server._pending_admin_pat_warning is not None


def test_query_failure_does_not_block_or_warn(capsys):
    client = MagicMock()
    client.execute.side_effect = RuntimeError("boom")
    with patch("rsc.config.load_config", return_value=MagicMock(token_uri=PAT_URI)), \
         patch.object(server, "_mcp_rsc_client", return_value=client):
        server._check_admin_pat()
    assert server._pending_admin_pat_warning is None
    assert "admin token check failed" in capsys.readouterr().err


def test_warning_attached_once_to_first_tool_result():
    server._pending_admin_pat_warning = server._ADMIN_PAT_WARNING

    @server.audit_tool
    def tool():
        return {"data": 1}

    first, second = tool(), tool()
    assert server._ADMIN_PAT_WARNING in first["_warning"]
    assert first["data"] == 1
    assert "_warning" not in second


def test_warning_not_consumed_by_non_dict_result():
    server._pending_admin_pat_warning = server._ADMIN_PAT_WARNING

    @server.audit_tool
    def tool():
        return ["not", "a", "dict"]

    assert tool() == ["not", "a", "dict"]
    assert server._pending_admin_pat_warning is not None
