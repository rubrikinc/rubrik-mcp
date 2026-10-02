"""
Unit tests for rubrik.version_check and its wiring into server.py.
No network or RSC credentials required.
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

import rubrik.server as server
from rubrik import version_check as vc


@pytest.fixture
def config_dir(tmp_path, monkeypatch):
    monkeypatch.setenv("RUBRIK_MCP_CONFIG_DIR", str(tmp_path))
    monkeypatch.delenv("RUBRIK_MCP_NO_UPDATE_CHECK", raising=False)
    return tmp_path


# ── Parsing and target selection ─────────────────────────────────────────────

@pytest.mark.parametrize("deployment,expected", [
    ("v20260518-53", "20260518"),
    ("v20261012-7", "20261012"),
    ("2.4.1", None),           # RSC-P format, not decoded yet
    ("", None),
])
def test_parse_tenant_date(deployment, expected):
    assert vc.parse_tenant_date(deployment) == expected


RELEASES = ["0.7.20260914", "0.8.20260928", "0.8.20261005", "0.8.20261019", "0.9.0rc1"]

@pytest.mark.parametrize("tenant,expected", [
    ("20261012", "0.8.20261005"),   # newest on or before the tenant, not the latest
    ("20261005", "0.8.20261005"),   # exact match
    ("20261101", "0.8.20261019"),
    ("20260901", None),             # tenant older than every release
])
def test_target_release(tenant, expected):
    assert vc.target_release(RELEASES, tenant) == expected


def test_target_release_prefers_higher_minor_on_same_date():
    assert vc.target_release(["0.8.20261005", "0.9.20261005"], "20261010") == "0.9.20261005"


def test_parse_pypi_releases_skips_empty_and_yanked():
    payload = {"releases": {
        "0.8.20260928": [{"yanked": False}],
        "0.8.20261005": [{"yanked": True}],
        "0.8.20261012": [],
    }}
    assert vc._parse_pypi_releases(payload) == ["0.8.20260928"]


# ── compute_status ───────────────────────────────────────────────────────────

def _versions(*vs):
    return lambda: list(vs)


def test_status_in_sync_does_not_query_pypi():
    fn = MagicMock()
    s = vc.compute_status("20260928", "v20260928-12", versions_fn=fn)
    assert s.state == vc.IN_SYNC
    fn.assert_not_called()


def test_status_index_ahead_does_not_query_pypi():
    fn = MagicMock()
    s = vc.compute_status("20261005", "v20260928-12", versions_fn=fn)
    assert s.state == vc.INDEX_AHEAD
    fn.assert_not_called()


def test_status_unknown_for_rscp_version():
    assert vc.compute_status("20260928", "2.4.1").state == vc.UNKNOWN


def test_status_update_available():
    with patch.object(vc, "install_method", return_value="pip"):
        s = vc.compute_status(
            "20260928", "v20261012-3",
            versions_fn=_versions("0.8.20260928", "0.8.20261005", "0.8.20261019"),
        )
    assert s.state == vc.UPDATE_AVAILABLE
    assert s.target_version == "0.8.20261005"
    assert "rubrik-mcp==0.8.20261005" in s.update_command


def test_status_awaiting_release_when_nothing_newer_fits():
    # Only a release newer than the tenant exists; that is not an upgrade for this tenant.
    s = vc.compute_status("20260928", "v20261012-3", versions_fn=_versions("0.8.20260928", "0.8.20261019"))
    assert s.state == vc.AWAITING_RELEASE
    assert s.target_version is None


def test_status_awaiting_release_when_pypi_unreachable():
    s = vc.compute_status("20260928", "v20261012-3", versions_fn=lambda: None)
    assert s.state == vc.AWAITING_RELEASE


# ── Messages ─────────────────────────────────────────────────────────────────

UPDATE = vc.SyncStatus(
    vc.UPDATE_AVAILABLE, "20260928", "v20261012-3", "20261012",
    "0.8.20261005", "Run `pip install rubrik-mcp==0.8.20261005`. Then restart your MCP client.",
)
AWAITING = vc.SyncStatus(vc.AWAITING_RELEASE, "20260928", "v20261012-3", "20261012")
AHEAD = vc.SyncStatus(vc.INDEX_AHEAD, "20261005", "v20260928-12", "20260928")
IN_SYNC = vc.SyncStatus(vc.IN_SYNC, "20260928", "v20260928-12", "20260928")


def test_instructions_notice_only_when_update_available():
    notice = vc.instructions_notice(UPDATE)
    assert "0.8.20261005" in notice and "restart your MCP client" in notice
    for s in (AWAITING, AHEAD, IN_SYNC):
        assert vc.instructions_notice(s) is None


def test_index_behind_note():
    assert "A matching release is available" in vc.index_behind_note(UPDATE)
    assert "No matching rubrik-mcp release" in vc.index_behind_note(AWAITING)
    assert vc.index_behind_note(AHEAD) is None
    assert vc.index_behind_note(IN_SYNC) is None


def test_index_ahead_note():
    assert "may not exist on this tenant" in vc.index_ahead_note(AHEAD)
    assert vc.index_ahead_note(UPDATE) is None


@pytest.mark.parametrize("method,needle", [
    ("uvx", "uvx rubrik-mcp@0.8.20261005"),
    ("uv-tool", "uv tool install --force rubrik-mcp==0.8.20261005"),
    ("docker", "Rebuild the rubrik-mcp image"),
    ("source", "checkout"),
    ("pip", "-m pip install rubrik-mcp==0.8.20261005"),
])
def test_update_command_per_install_method(method, needle):
    cmd = vc.update_command("0.8.20261005", method)
    assert needle in cmd
    assert cmd.endswith("Then restart your MCP client.")


def test_no_em_dashes_in_user_facing_text():
    texts = [vc.instructions_notice(UPDATE), vc.index_behind_note(UPDATE),
             vc.index_behind_note(AWAITING), vc.index_ahead_note(AHEAD)]
    texts += [vc.update_command("0.8.20261005", m) for m in ("uvx", "uv-tool", "docker", "source", "pip")]
    assert not any("\u2014" in t for t in texts)


# ── PyPI lookup and cache ────────────────────────────────────────────────────

def _pypi_response(versions):
    resp = MagicMock()
    resp.__enter__.return_value = resp
    resp.read.return_value = json.dumps(
        {"releases": {v: [{"yanked": False}] for v in versions}}
    ).encode()
    return resp


def test_published_versions_fetches_and_caches(config_dir):
    with patch.object(vc.urllib.request, "urlopen", return_value=_pypi_response(["0.8.20261005"])) as op:
        assert vc.published_versions() == ["0.8.20261005"]
        assert vc.published_versions() == ["0.8.20261005"]
    assert op.call_count == 1
    assert (config_dir / vc.CACHE_FILE).exists()


def test_published_versions_refreshes_stale_cache(config_dir):
    stale = datetime.now(timezone.utc) - timedelta(hours=25)
    (config_dir / vc.CACHE_FILE).write_text(json.dumps(
        {"checked_at": stale.isoformat(), "versions": ["0.8.20260928"]}))
    with patch.object(vc.urllib.request, "urlopen", return_value=_pypi_response(["0.8.20261005"])):
        assert vc.published_versions() == ["0.8.20261005"]


def test_published_versions_falls_back_to_stale_cache_offline(config_dir):
    stale = datetime.now(timezone.utc) - timedelta(days=3)
    (config_dir / vc.CACHE_FILE).write_text(json.dumps(
        {"checked_at": stale.isoformat(), "versions": ["0.8.20260928"]}))
    with patch.object(vc.urllib.request, "urlopen", side_effect=OSError("offline")):
        assert vc.published_versions() == ["0.8.20260928"]


def test_published_versions_offline_without_cache(config_dir):
    with patch.object(vc.urllib.request, "urlopen", side_effect=OSError("offline")):
        assert vc.published_versions() is None


def test_published_versions_opt_out(config_dir, monkeypatch):
    monkeypatch.setenv("RUBRIK_MCP_NO_UPDATE_CHECK", "1")
    with patch.object(vc.urllib.request, "urlopen") as op:
        assert vc.published_versions() is None
    op.assert_not_called()


# ── Server wiring ────────────────────────────────────────────────────────────

@pytest.fixture
def reset_server_state(monkeypatch):
    monkeypatch.setattr(server, "_SYNC_STATUS", None)
    monkeypatch.setattr(server, "_SEARCH_NOTE_SENT", False)
    original = server.mcp._mcp_server.instructions
    yield
    server.mcp._mcp_server.instructions = original


def _fake_client(deployment):
    client = MagicMock()
    client.execute.return_value = {"data": {"deploymentVersion": deployment}}
    return client


def test_check_schema_sync_appends_notice_to_instructions(reset_server_state, monkeypatch):
    monkeypatch.setattr(server, "field_index_schema_version", lambda: "20260928")
    monkeypatch.setattr(server, "_mcp_rsc_client", lambda: _fake_client("v20261012-3"))
    monkeypatch.setattr(vc, "published_versions", lambda: ["0.8.20261005"])
    monkeypatch.setattr(vc, "install_method", lambda: "pip")
    server._check_schema_sync()
    assert server._SYNC_STATUS.state == vc.UPDATE_AVAILABLE
    assert "UPDATE AVAILABLE" in server.mcp.instructions
    assert server.mcp.instructions.startswith(server._BASE_INSTRUCTIONS)


def test_check_schema_sync_in_sync_leaves_instructions(reset_server_state, monkeypatch):
    before = server.mcp.instructions
    monkeypatch.setattr(server, "field_index_schema_version", lambda: "20260928")
    monkeypatch.setattr(server, "_mcp_rsc_client", lambda: _fake_client("v20260928-3"))
    server._check_schema_sync()
    assert server._SYNC_STATUS.state == vc.IN_SYNC
    assert server.mcp.instructions == before


def test_check_schema_sync_survives_missing_credentials(reset_server_state, monkeypatch, capsys):
    def boom():
        raise RuntimeError("no credentials")
    monkeypatch.setattr(server, "_mcp_rsc_client", boom)
    server._check_schema_sync()
    assert server._SYNC_STATUS is None
    assert "schema sync check failed" in capsys.readouterr().err


def test_search_attaches_behind_note_once(reset_server_state, monkeypatch):
    monkeypatch.setattr(server, "_SYNC_STATUS", AWAITING)
    first = server.rsc_search_schema("virtual machine")
    second = server.rsc_search_schema("virtual machine")
    assert "index_note" in first
    assert "index_note" not in second


def test_search_attaches_behind_note_on_empty_results(reset_server_state, monkeypatch):
    monkeypatch.setattr(server, "_SYNC_STATUS", AWAITING)
    monkeypatch.setattr(server, "_SEARCH_NOTE_SENT", True)
    monkeypatch.setattr(server, "search_operations", lambda *a, **k: [])
    monkeypatch.setattr(server, "search_fields", lambda *a, **k: [])
    monkeypatch.setattr(server, "_SEARCH_TYPES_AVAILABLE", False)
    assert "index_note" in server.rsc_search_schema("brand new thing")


def test_search_no_note_when_in_sync(reset_server_state, monkeypatch):
    monkeypatch.setattr(server, "_SYNC_STATUS", IN_SYNC)
    assert "index_note" not in server.rsc_search_schema("virtual machine")


def test_describe_miss_includes_behind_note(reset_server_state, monkeypatch):
    monkeypatch.setattr(server, "_SYNC_STATUS", UPDATE)
    with pytest.raises(ValueError, match="A matching release is available"):
        server.rsc_describe_operation_full("operationFromTheFuture", "query")


def test_describe_miss_unchanged_when_in_sync(reset_server_state, monkeypatch):
    monkeypatch.setattr(server, "_SYNC_STATUS", IN_SYNC)
    with pytest.raises(ValueError) as exc:
        server.rsc_describe_operation_full("operationFromTheFuture", "query")
    assert "schema index" not in str(exc.value)


def test_execute_attaches_ahead_note_on_unknown_field(reset_server_state, monkeypatch):
    monkeypatch.setattr(server, "_SYNC_STATUS", AHEAD)
    client = MagicMock()
    client.execute.return_value = {
        "data": None, "errors": [{"message": "Cannot query field 'shinyNewThing' on type 'Query'."}]}
    monkeypatch.setattr(server, "_mcp_rsc_client", lambda: client)
    result = server.rsc_execute_operation("query { shinyNewThing { id } }")
    assert "may not exist on this tenant" in result["index_note"]


def test_execute_no_note_on_other_errors(reset_server_state, monkeypatch):
    monkeypatch.setattr(server, "_SYNC_STATUS", AHEAD)
    client = MagicMock()
    client.execute.return_value = {"data": None, "errors": [{"message": "Permission denied"}]}
    monkeypatch.setattr(server, "_mcp_rsc_client", lambda: client)
    assert "index_note" not in server.rsc_execute_operation("query { accountId }")
