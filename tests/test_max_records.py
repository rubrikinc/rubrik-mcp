"""max_records cap: env resolution and that rsc_execute_operation passes it."""
import pytest

from rubrik import policy
from rubrik import server


@pytest.mark.parametrize("env,expected", [
    (None, 10000),    # unset -> default
    ("2000", 2000),   # valid override
    ("abc", 10000),   # non-integer -> default (no crash)
    ("", 10000),      # empty -> default
    ("0", 10000),     # non-positive -> default (0 would disable the cap)
    ("-5", 10000),    # negative -> default
])
def test_resolve_max_records(monkeypatch, env, expected):
    if env is None:
        monkeypatch.delenv("RUBRIK_MCP_MAX_RECORDS", raising=False)
    else:
        monkeypatch.setenv("RUBRIK_MCP_MAX_RECORDS", env)
    assert server._resolve_max_records() == expected


def test_execute_operation_passes_max_records(monkeypatch):
    # rsc_execute_operation must bound pagination by passing the cap to the client.
    monkeypatch.delenv("RUBRIK_MCP_MAX_RECORDS", raising=False)
    monkeypatch.setattr(server, "_POLICY", policy.Policy(policy.default_data()))
    captured = {}

    class _FakeClient:
        def execute(self, operation, variables=None, max_records=None):
            captured["max_records"] = max_records
            return {"data": {"ok": True}}

    monkeypatch.setattr(server, "_mcp_rsc_client", lambda: _FakeClient())
    server.rsc_execute_operation("query { slaDomains { nodes { id } } }")
    assert captured["max_records"] == server._resolve_max_records()


def _fake_conn_client(captured, *, count=0, nodes=None):
    """Fake RSC client capturing the max_records the tool passes, returning a
    minimal connection shape both built-in tools can consume."""
    nodes = nodes if nodes is not None else []

    class _FakeClient:
        def execute(self, operation, variables=None, max_records=None):
            captured["max_records"] = max_records
            field = ("snappableConnection" if "snappable" in operation.lower()
                     or "Workload" in operation else "activitySeriesConnection")
            return {"data": {field: {
                "count": count,
                "nodes": list(nodes),
                "pageInfo": {"hasNextPage": False, "endCursor": None},
            }}}

    return _FakeClient()


def test_max_records_resolved_live_not_frozen(monkeypatch):
    # Regression for the frozen-constant bug: the cap must be resolved at CALL
    # time, so an env var set after import is honored (not baked in at import).
    captured = {}
    monkeypatch.setattr(server, "_mcp_rsc_client", lambda: _fake_conn_client(captured))
    monkeypatch.setenv("RUBRIK_MCP_MAX_RECORDS", "137")
    server.rsc_get_workloads()
    assert captured["max_records"] == 137


def test_limit_zero_is_a_real_cap(monkeypatch):
    # limit=0 must pass 0 (return nothing), not fall through to the default cap.
    captured = {}
    monkeypatch.setattr(server, "_mcp_rsc_client", lambda: _fake_conn_client(captured))
    result = server.rsc_get_workloads(limit=0)
    assert captured["max_records"] == 0
    assert result["workloads"] == []


def test_negative_limit_rejected(monkeypatch):
    monkeypatch.setattr(server, "_mcp_rsc_client", lambda: _fake_conn_client({}))
    with pytest.raises(ValueError):
        server.rsc_get_workloads(limit=-1)
    with pytest.raises(ValueError):
        server.rsc_get_events(limit=-1)


def test_workloads_return_is_structured_and_truncated(monkeypatch):
    # count > returned -> truncated True, surfaced in the return value (not stderr).
    captured = {}
    nodes = [{"fid": str(i)} for i in range(5)]
    monkeypatch.setattr(
        server, "_mcp_rsc_client",
        lambda: _fake_conn_client(captured, count=42, nodes=nodes),
    )
    result = server.rsc_get_workloads(limit=5)
    assert result["count"] == 42
    assert result["returned"] == 5
    assert result["truncated"] is True
    assert len(result["workloads"]) == 5
