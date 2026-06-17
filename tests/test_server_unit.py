"""
Unit tests for rubrik.server — no RSC credentials required (mock-based).

Run on every PR. Covers the design-doc Test Plan helpers plus the validation
paths of the discovery/execution/write tools, using the functions as they
actually exist in this repo's server.py.
"""

import json
from unittest.mock import MagicMock, patch

import pytest

import rubrik.server as server


# ── 1. Import smoke ───────────────────────────────────────────────────────────

def test_server_imports_cleanly():
    assert callable(server.main)
    assert hasattr(server, "mcp")          # FastMCP instance


# ── 2. _is_mutation ───────────────────────────────────────────────────────────

@pytest.mark.parametrize("op,expected", [
    ("mutation TakeSnapshot($i: X!) { takeOnDemandSnapshot(input: $i) { id } }", True),
    ("query { accountId }", False),
    ("query GetWorkloads { snappableConnection { nodes { id } } }", False),
    ("MUTATION { doSomething }", True),                       # case-insensitive
    ('query { field(arg: "mutation") }', True),               # known regex limitation — documents behavior
])
def test_is_mutation(op, expected):
    assert server._is_mutation(op) is expected


# ── 3. _resolve_refs ─────────────────────────────────────────────────────────

def test_resolve_refs_simple():
    assert server._resolve_refs("${s.id}", {"s": {"id": "abc"}}) == "abc"

def test_resolve_refs_nested():
    assert server._resolve_refs("${s.node.name}", {"s": {"node": {"name": "vm01"}}}) == "vm01"

def test_resolve_refs_list_index():
    ctx = {"s": [{"id": "x"}, {"id": "y"}]}
    assert server._resolve_refs("${s.0.id}", ctx) == "x"
    assert server._resolve_refs("${s.1.id}", ctx) == "y"

def test_resolve_refs_missing_returns_none():
    assert server._resolve_refs("${s.missing}", {"s": {}}) is None

def test_resolve_refs_passthrough_and_dict():
    assert server._resolve_refs("plain", {}) == "plain"
    assert server._resolve_refs(42, {}) == 42
    assert server._resolve_refs({"workload_id": "${s.id}"}, {"s": {"id": "a"}}) == {"workload_id": "a"}


# ── 4. _normalise / _data_or_raise ───────────────────────────────────────────

def test_normalise_passes_through_dict():
    d = {"data": {"accountId": "x"}}
    assert server._normalise(d) == d

def test_data_or_raise_extracts_field():
    raw = {"data": {"taskchain": {"state": "SUCCEEDED"}}}
    assert server._data_or_raise(raw, "taskchain") == {"state": "SUCCEEDED"}

def test_data_or_raise_raises_on_graphql_errors():
    raw = {"errors": [{"message": "Objects are not authorized"}], "data": None}
    with pytest.raises(RuntimeError, match="Objects are not authorized"):
        server._data_or_raise(raw, "taskchain")

def test_data_or_raise_absent_field_returns_empty():
    assert server._data_or_raise({"data": {}}, "taskchain") == {}


# ── 5. _poll_once ────────────────────────────────────────────────────────────

def test_poll_once_unsupported_type_raises():
    with pytest.raises(ValueError, match="Cannot poll job status"):
        server._poll_once(MagicMock(), "job-1", "NotAType", None)

def test_poll_once_cloud_native_maps_terminal_state():
    client = MagicMock()
    client.execute.return_value = {"data": {"taskchain": {"state": "SUCCEEDED", "progress": 100}}}
    result = server._poll_once(client, "job-1", "AzureNativeVm", None)
    assert result["status"] == "SUCCEEDED"
    assert result["done"] is True


# ── 6. Workflow loader + executor ────────────────────────────────────────────

def test_load_workflows_skips_malformed(tmp_path, monkeypatch):
    good = tmp_path / "good.json"
    good.write_text(json.dumps({
        "schema_version": 1, "version": 1,
        "name": "test_wf", "description": "d", "steps": []
    }))
    (tmp_path / "bad.json").write_text("{ not valid json }")

    monkeypatch.setattr(server, "_WORKFLOWS_DIR", tmp_path)
    registered = []
    with patch.object(server, "_register_workflow", side_effect=lambda s: registered.append(s["name"])):
        server._load_workflows()          # must not raise on bad.json
    assert "test_wf" in registered

def test_execute_workflow_single_step_returns_result():
    spec = {
        "schema_version": 1, "name": "t", "description": "d",
        "steps": [{"id": "w", "mcp": "rubrik", "tool": "rsc_get_workloads", "args": {}}],
    }
    with patch.dict(server._TOOL_REGISTRY, {"rsc_get_workloads": lambda **kw: [{"id": "wl-1"}]}, clear=False):
        assert server._execute_workflow(spec) == [{"id": "wl-1"}]


# ── 7. Discovery empty-search guards ─────────────────────────────────────────

def test_search_operations_rejects_empty():
    with pytest.raises(ValueError, match="must not be empty"):
        server.rsc_search_operations("")

def test_search_fields_rejects_blank():
    with pytest.raises(ValueError, match="must not be empty"):
        server.rsc_search_fields("   ")


# ── 8. rsc_execute_operation gate ────────────────────────────────────────────

def test_execute_operation_blocks_mutation_before_rsc():
    with patch.object(server, "RSCClient") as mock_client:
        result = server.rsc_execute_operation(
            "mutation TakeSnapshot { takeOnDemandSnapshot(input: {id: \"x\"}) { id } }"
        )
        mock_client.assert_not_called()
    assert result["error"] == "mutation_blocked"
    assert "blocked_operation" in result

def test_execute_operation_passes_query_through():
    inst = MagicMock()
    inst.execute.return_value = {"data": {"accountId": "x"}}
    with patch.object(server, "RSCClient", return_value=inst):
        result = server.rsc_execute_operation("query { accountId }")
    assert result.get("error") != "mutation_blocked"
    inst.execute.assert_called_once()


# ── 9. Write-tool validation (mock client; no live calls) ────────────────────

def test_take_on_demand_snapshot_unsupported_type():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="Unsupported objectType"):
            server.rsc_take_on_demand_snapshot(workload_id="x", object_type="NotAType")

def test_onboard_host_requires_cluster_uuid():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="cluster_uuid is required"):
            server.rsc_onboard_host(target="host.example", host_type="PHYSICAL")

def test_onboard_host_unsupported_type():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="Unsupported host_type"):
            server.rsc_onboard_host(target="host.example", host_type="BOGUS")

def test_assign_sla_requires_sla_id_for_protect():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="sla_id is required"):
            server.rsc_assign_sla(object_ids=["fid-1"])          # default assign_type=protectWithSlaId
