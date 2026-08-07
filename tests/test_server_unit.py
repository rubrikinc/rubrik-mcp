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
    # "mutation" inside a string literal or comment is NOT a mutation (stripped first)
    ('query { field(arg: "mutation") }', False),
    ("# run the mutation\nquery { accountId }", False),
    # ...but a real mutation is still caught in any operation position / after a comment
    ("query Q { a }\nmutation M { b }", True),
    ("# go\nmutation M { b }", True),
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

    monkeypatch.setattr(server, "_workflows_dir", lambda: tmp_path)
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


# ── 7. Tool surface ───────────────────────────────────────────────────────────

def test_tool_surface():
    """Assert the exact set of tools the server exposes.

    Fails loudly when a tool is added or removed without updating this test,
    ensuring the version is bumped and docs are kept in sync.
    """
    import asyncio
    tools = asyncio.run(server.mcp.list_tools())
    names = {t.name for t in tools}

    expected = {
        # Discovery
        "rsc_search_schema",
        "rsc_describe_operation_full",
        "rsc_describe_type",
        # Curated
        "rsc_get_workloads",
        "rsc_get_events",
        "rsc_get_clusters",
        "rsc_get_sla_domains",
        "rsc_wait_for_job",
        "rsc_search_help",
        # Execution
        "rsc_execute_operation",
        # Workflows
        "rsc_save_workflow",
        "rsc_list_workflows",
        "rsc_delete_workflow",
    }

    assert names == expected, (
        f"Tool surface changed.\n"
        f"  Unexpected tools present: {names - expected}\n"
        f"  Expected tools missing:   {expected - names}\n"
        "Update this test, bump the version, and update docs."
    )


# ── 8. Discovery empty-search guard ──────────────────────────────────────────

def test_search_schema_rejects_empty():
    with pytest.raises(ValueError, match="must not be empty"):
        server.rsc_search_schema("")

def test_search_schema_rejects_blank():
    with pytest.raises(ValueError, match="must not be empty"):
        server.rsc_search_schema("   ")


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

def test_take_on_demand_snapshot_cdm_returns_cluster_id():
    cluster_lookup = {"data": {"snappableConnection": {"nodes": [{"cluster": {"id": "cluster-uuid-123"}}]}}}
    mutation_result = {"data": {"vsphereOnDemandSnapshot": {"id": "job-id-456:::0", "status": "QUEUED"}}}
    inst = MagicMock()
    inst.execute.side_effect = [cluster_lookup, mutation_result]
    with patch.object(server, "RSCClient", return_value=inst):
        result = server.rsc_take_on_demand_snapshot(workload_id="vm-fid", object_type="VmwareVirtualMachine")
    assert result["cluster_id"] == "cluster-uuid-123"
    assert result["id"] == "job-id-456:::0"

def test_take_on_demand_snapshot_cdm_cluster_lookup_failure_is_nonfatal():
    inst = MagicMock()
    inst.execute.side_effect = [
        RuntimeError("lookup failed"),
        {"data": {"vsphereOnDemandSnapshot": {"id": "job-id:::0", "status": "QUEUED"}}},
    ]
    with patch.object(server, "RSCClient", return_value=inst):
        result = server.rsc_take_on_demand_snapshot(workload_id="vm-fid", object_type="VmwareVirtualMachine")
    assert "cluster_id" not in result
    assert result["id"] == "job-id:::0"

def test_take_on_demand_snapshot_cloud_native_has_no_cluster_id():
    inst = MagicMock()
    inst.execute.return_value = {"data": {"takeOnDemandSnapshot": {"taskchainUuids": [], "errors": []}}}
    with patch.object(server, "RSCClient", return_value=inst):
        result = server.rsc_take_on_demand_snapshot(workload_id="vm-fid", object_type="AzureNativeVm")
    assert "cluster_id" not in result

def test_onboard_host_requires_cluster_uuid():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="cluster_uuid is required"):
            server.rsc_onboard_host(target="host.example", host_type="PHYSICAL")

def test_onboard_host_unsupported_type():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="Unsupported host_type"):
            server.rsc_onboard_host(target="host.example", host_type="BOGUS")

def test_search_help_rejects_negative_limit():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="limit must be"):
            server.rsc_search_help(query="ransomware", limit=-1)


def test_search_help_rejects_unknown_source():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="source must be one of"):
            server.rsc_search_help(query="ransomware", source="BLOG_POSTS")


def test_assign_sla_requires_sla_id_for_protect():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="sla_id is required"):
            server.rsc_assign_sla(object_ids=["fid-1"])          # default assign_type=protectWithSlaId

# ── 10. rsc_get_workloads filter validation ───────────────────────────────────

def test_get_workloads_rejects_invalid_object_state():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="object_state must be one of"):
            server.rsc_get_workloads(object_state="BOGUS")

def test_get_workloads_rejects_object_type_with_excluded():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="cannot both be specified"):
            server.rsc_get_workloads(object_type="VmwareVirtualMachine", excluded_object_types=["NutanixVirtualMachine"])

def test_get_workloads_builds_sla_filter():
    inst = MagicMock()
    inst.execute.return_value = {"data": {"snappableConnection": {"count": 0, "nodes": [], "pageInfo": {"hasNextPage": False, "endCursor": None}}}}
    with patch.object(server, "RSCClient", return_value=inst):
        server.rsc_get_workloads(sla_id="sla-uuid-123")
    call_vars = inst.execute.call_args[1]["variables"]
    assert call_vars["filter"]["slaDomain"] == {"id": ["sla-uuid-123"]}



# ── 10. rsc_get_clusters ──────────────────────────────────────────────────────

def test_get_clusters_rejects_negative_limit():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="limit must be"):
            server.rsc_get_clusters(limit=-1)


def test_get_clusters_returns_structured_result():
    inst = MagicMock()
    inst.execute.return_value = {
        "data": {
            "allClusterConnection": {
                "count": 1,
                "nodes": [{"id": "c1", "name": "prod-cluster", "status": "Connected"}],
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }
        }
    }
    with patch.object(server, "RSCClient", return_value=inst):
        result = server.rsc_get_clusters()
    assert result["count"] == 1
    assert result["returned"] == 1
    assert result["truncated"] is False
    assert result["clusters"][0]["name"] == "prod-cluster"


def test_get_clusters_applies_status_filter():
    inst = MagicMock()
    inst.execute.return_value = {
        "data": {
            "allClusterConnection": {
                "count": 0,
                "nodes": [],
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }
        }
    }
    with patch.object(server, "RSCClient", return_value=inst):
        server.rsc_get_clusters(status="Disconnected")
    call_kwargs = inst.execute.call_args
    variables = call_kwargs[1].get("variables") or call_kwargs[0][1]
    assert variables["filter"]["connectionState"] == ["Disconnected"]


def test_get_clusters_caps_limit_at_100():
    inst = MagicMock()
    inst.execute.return_value = {
        "data": {
            "allClusterConnection": {
                "count": 0,
                "nodes": [],
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }
        }
    }
    with patch.object(server, "RSCClient", return_value=inst):
        server.rsc_get_clusters(limit=999)
    call_kwargs = inst.execute.call_args
    # max_records is passed as a kwarg; confirm it is capped at 100
    max_records = call_kwargs[1].get("max_records")
    assert max_records == 100


# ── 11. rsc_get_sla_domains ───────────────────────────────────────────────────

def test_get_sla_domains_rejects_negative_limit():
    with patch.object(server, "RSCClient"):
        with pytest.raises(ValueError, match="limit must be"):
            server.rsc_get_sla_domains(limit=-1)


def test_get_sla_domains_returns_structured_result():
    inst = MagicMock()
    inst.execute.return_value = {
        "data": {
            "slaDomains": {
                "count": 2,
                "nodes": [
                    {"id": "s1", "name": "Gold", "isRetentionLockedSla": True},
                    {"id": "s2", "name": "Silver", "isRetentionLockedSla": False},
                ],
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }
        }
    }
    with patch.object(server, "RSCClient", return_value=inst):
        result = server.rsc_get_sla_domains()
    assert result["count"] == 2
    assert result["returned"] == 2
    assert len(result["sla_domains"]) == 2


def test_get_sla_domains_client_side_retention_lock_filter():
    inst = MagicMock()
    inst.execute.return_value = {
        "data": {
            "slaDomains": {
                "count": 2,
                "nodes": [
                    {"id": "s1", "name": "Gold", "isRetentionLockedSla": True},
                    {"id": "s2", "name": "Silver", "isRetentionLockedSla": False},
                ],
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }
        }
    }
    with patch.object(server, "RSCClient", return_value=inst):
        result = server.rsc_get_sla_domains(is_retention_locked=True)
    assert result["returned"] == 1
    assert result["sla_domains"][0]["id"] == "s1"


def test_get_sla_domains_name_filter_builds_correct_payload():
    inst = MagicMock()
    inst.execute.return_value = {
        "data": {
            "slaDomains": {
                "count": 0,
                "nodes": [],
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }
        }
    }
    with patch.object(server, "RSCClient", return_value=inst):
        server.rsc_get_sla_domains(name_contains="Gold", cluster_id="uuid-1")
    call_kwargs = inst.execute.call_args
    variables = call_kwargs[1].get("variables") or call_kwargs[0][1]
    filter_list = variables["filter"]
    fields = {f["field"]: f for f in filter_list}
    assert fields["NAME"]["text"] == "Gold"
    assert fields["CLUSTER_UUID"]["textList"] == ["uuid-1"]


def test_get_sla_domains_caps_limit_at_200():
    inst = MagicMock()
    inst.execute.return_value = {
        "data": {
            "slaDomains": {
                "count": 0,
                "nodes": [],
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }
        }
    }
    with patch.object(server, "RSCClient", return_value=inst):
        server.rsc_get_sla_domains(limit=9999)
    call_kwargs = inst.execute.call_args
    max_records = call_kwargs[1].get("max_records")
    assert max_records == 200
