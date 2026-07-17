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
    monkeypatch.setattr(server, "_POLICY", policy.Policy(policy.default_data()))
    captured = {}

    class _FakeClient:
        def execute(self, operation, variables=None, max_records=None):
            captured["max_records"] = max_records
            return {"data": {"ok": True}}

    monkeypatch.setattr(server, "_mcp_rsc_client", lambda: _FakeClient())
    server.rsc_execute_operation("query { slaDomains { nodes { id } } }")
    assert captured["max_records"] == server._DEFAULT_MAX_RECORDS
