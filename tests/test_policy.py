"""Tests for the allow/deny gating policy (policy.py) and its enforcement points
in server.py: reads denylist, cross-MCP egress allowlist, and register-time
write-tool gating.

None of these tests contact RSC — every gated path returns before any RSC call,
so no credentials are required.
"""

import json
import random

import pytest

from rubrik import policy
from rubrik import server


# --------------------------------------------------------------------------- #
# policy.py — RUBRIK_MCP_CONFIG_DIR resolution
# --------------------------------------------------------------------------- #

def test_rubrik_dir_defaults_to_home(monkeypatch):
    monkeypatch.delenv("RUBRIK_MCP_CONFIG_DIR", raising=False)
    from pathlib import Path
    assert policy.rubrik_dir() == Path.home() / ".rubrik"


def test_rubrik_dir_honors_env_override(monkeypatch, tmp_path):
    monkeypatch.setenv("RUBRIK_MCP_CONFIG_DIR", str(tmp_path))
    from pathlib import Path
    assert policy.rubrik_dir() == Path(tmp_path)
    # and the policy path derives from it
    assert policy.rubrik_dir() / "mcp-policy.json" == tmp_path / "mcp-policy.json"


def test_rubrik_home_seeds_policy_under_override(monkeypatch, tmp_path):
    monkeypatch.setenv("RUBRIK_MCP_CONFIG_DIR", str(tmp_path))
    pf = policy.rubrik_dir() / "mcp-policy.json"
    policy.load(pf)
    assert pf.exists()
    assert pf.parent == tmp_path


def test_policy_path_resolves_live(monkeypatch, tmp_path):
    # policy_path() must reflect an env change made AFTER import — it is a
    # function, not a module-level constant frozen at import time.
    monkeypatch.setenv("RUBRIK_MCP_CONFIG_DIR", str(tmp_path))
    assert policy.policy_path() == tmp_path / "mcp-policy.json"


def test_load_no_arg_honors_env_override_at_call_time(monkeypatch, tmp_path):
    # The no-arg load() is exactly what main() calls. It must seed under the
    # override set at call time, NOT a path frozen when policy.py was imported.
    # This is the regression guard for the frozen-default-argument bug.
    monkeypatch.setenv("RUBRIK_MCP_CONFIG_DIR", str(tmp_path))
    pol = policy.load()
    assert (tmp_path / "mcp-policy.json").exists()
    assert pol is not None


def test_workflows_dir_honors_env_override(monkeypatch, tmp_path):
    # server._workflows_dir() must resolve live too (same class of bug as the
    # policy path): a frozen module constant would ignore this env change.
    monkeypatch.setenv("RUBRIK_MCP_CONFIG_DIR", str(tmp_path))
    assert server._workflows_dir() == tmp_path / "workflows"


# --------------------------------------------------------------------------- #
# policy.py — load / seed / merge / validate
# --------------------------------------------------------------------------- #

def test_absent_file_seeds_secure_default_template(tmp_path):
    pf = tmp_path / "mcp-policy.json"
    p = policy.load(pf)
    assert pf.exists()
    assert oct(pf.stat().st_mode)[-3:] == "600"  # secret-ish perms
    seed = json.loads(pf.read_text())
    # allowlist-only shape: no allow_by_default / denied for cross-MCP egress
    assert seed["cross_mcp_egress"] == {"allowed": []}
    assert "_comment" in seed
    assert p.writes_enabled and p.query_allowed("anything")


def test_absent_file_without_seed_returns_defaults(tmp_path):
    p = policy.load(tmp_path / "nope.json", seed_if_absent=False)
    assert not (tmp_path / "nope.json").exists()
    assert p.writes_enabled


def test_partial_file_merges_onto_defaults(tmp_path):
    pf = tmp_path / "mcp-policy.json"
    pf.write_text('{"writes_enabled": false}')
    p = policy.load(pf)
    assert not p.writes_enabled
    assert p.query_allowed("x")  # queries block still defaulted in


def test_malformed_json_raises(tmp_path):
    pf = tmp_path / "mcp-policy.json"
    pf.write_text("{ not valid json")
    with pytest.raises(policy.PolicyError):
        policy.load(pf)


@pytest.mark.parametrize("body", [
    '{"writes_enabled": "yes"}',
    '{"write_tools": {"a": "on"}}',
    '{"queries": {"allow_by_default": 1}}',
    '{"queries": {"denied": "o365Teams"}}',
    '{"cross_mcp_egress": {"allowed": "slack"}}',
])
def test_wrong_types_raise(tmp_path, body):
    pf = tmp_path / "mcp-policy.json"
    pf.write_text(body)
    with pytest.raises(policy.PolicyError):
        policy.load(pf)


# --------------------------------------------------------------------------- #
# Policy decision logic (precedence, defaults, master switch)
# --------------------------------------------------------------------------- #

def test_query_precedence_denied_beats_allowed():
    p = policy.Policy({
        **policy.default_data(),
        "queries": {"allow_by_default": True, "allowed": ["x"], "denied": ["x"]},
    })
    assert not p.query_allowed("x")          # denied wins
    assert p.query_allowed("other")          # allow-by-default


def test_query_strict_allowlist_mode():
    p = policy.Policy({
        **policy.default_data(),
        "queries": {"allow_by_default": False, "allowed": ["ok"], "denied": []},
    })
    assert p.query_allowed("ok")
    assert not p.query_allowed("anythingelse")


def test_cross_mcp_is_allowlist_only():
    p = policy.Policy(policy.default_data())         # empty allowlist
    assert not p.cross_mcp_allowed("slack")
    p2 = policy.Policy({**policy.default_data(),
                        "cross_mcp_egress": {"allowed": ["slack"]}})
    assert p2.cross_mcp_allowed("slack")
    assert not p2.cross_mcp_allowed("email")


def test_write_master_switch_and_sparse_map():
    off = policy.Policy({**policy.default_data(), "writes_enabled": False})
    assert not off.write_tool_enabled("rsc_assign_sla")

    p = policy.Policy({**policy.default_data(),
                       "write_tools": {"rsc_assign_sla": False}})
    assert not p.write_tool_enabled("rsc_assign_sla")
    assert p.write_tool_enabled("rsc_onboard_host")     # unlisted -> enabled
    assert p.write_tool_enabled("rsc_future_tool")      # omitted -> enabled


def test_any_writes_enabled_drives_startup_warning():
    # Default: writes on, tools enabled -> warn.
    assert policy.Policy(policy.default_data()).any_writes_enabled()
    # Master switch off -> no warning.
    assert not policy.Policy(
        {**policy.default_data(), "writes_enabled": False}
    ).any_writes_enabled()
    # Master on but every curated write tool individually disabled -> no writes exposed.
    all_off = {name: False for name in policy.WRITE_TOOL_NAMES}
    assert not policy.Policy(
        {**policy.default_data(), "write_tools": all_off}
    ).any_writes_enabled()


# --------------------------------------------------------------------------- #
# server.py enforcement — reads denylist
# --------------------------------------------------------------------------- #

@pytest.fixture
def restore_policy():
    # Save/restore both the policy and the tool registry: tests that assert on
    # registration state (e.g. a disabled write tool absent from _TOOL_REGISTRY)
    # are order-dependent otherwise, since main()/registration mutate the
    # module-level registry.
    saved = server._POLICY
    saved_registry = dict(server._TOOL_REGISTRY)
    yield
    server._POLICY = saved
    server._TOOL_REGISTRY.clear()
    server._TOOL_REGISTRY.update(saved_registry)


def test_denied_query_blocked_before_rsc_call(restore_policy):
    server._POLICY = policy.Policy({
        **policy.default_data(),
        "queries": {"allow_by_default": True, "allowed": [], "denied": ["o365Teams"]},
    })
    out = server.rsc_execute_operation("query { o365Teams { nodes { id } } }")
    assert out["error"] == "query_blocked_by_policy"
    assert out["blocked_fields"] == ["o365Teams"]
    assert "do not retry" in out["message"].lower()


def test_allowed_query_passes_gate(monkeypatch, restore_policy):
    server._POLICY = policy.Policy(policy.default_data())  # allow-by-default

    called = {}

    class _FakeClient:
        def execute(self, operation, variables=None, max_records=None):
            called["op"] = operation
            called["max_records"] = max_records
            return {"data": {"ok": True}}

    monkeypatch.setattr(server, "_mcp_rsc_client", lambda: _FakeClient())
    out = server.rsc_execute_operation("query { slaDomains { nodes { id } } }")
    assert called["op"]           # gate let it through to the client
    assert out == {"data": {"ok": True}}


# --------------------------------------------------------------------------- #
# server.py enforcement — cross-MCP egress allowlist
# --------------------------------------------------------------------------- #

def _external_step_spec():
    return {
        "schema_version": 1,
        "name": "x",
        "description": "d",
        "steps": [
            {"id": "leak", "mcp": "slack", "tool": "post_message",
             "args": {"text": "${_args.secret}"}},
        ],
    }


def test_cross_mcp_blocked_when_not_allowlisted(restore_policy):
    server._POLICY = policy.Policy(policy.default_data())  # empty allowlist
    out = server._execute_workflow(_external_step_spec(), {"secret": "top-secret"})
    assert out["error"] == "cross_mcp_egress_blocked_by_policy"
    assert out["blocked_mcp"] == "slack"
    # value must not be materialized anywhere in the blocked response
    assert "top-secret" not in json.dumps(out)


def test_cross_mcp_allowed_when_listed(restore_policy):
    server._POLICY = policy.Policy({**policy.default_data(),
                                    "cross_mcp_egress": {"allowed": ["slack"]}})
    out = server._execute_workflow(_external_step_spec(), {"secret": "top-secret"})
    assert "next_steps" in out
    assert out["next_steps"][0]["mcp"] == "slack"
    # now the value IS resolved into the pending (allowlisted) step
    assert out["next_steps"][0]["args"]["text"] == "top-secret"


def test_cross_mcp_block_withholds_prior_rsc_read_data(restore_policy):
    # A workflow whose FIRST step is an RSC read and whose second step tries to
    # egress that read to a non-allowlisted MCP. The block response must contain
    # none of the read's data (no 'completed' echo) — nothing rides back out on a
    # path that was heading to a blocked destination.
    server._POLICY = policy.Policy(policy.default_data())  # empty allowlist
    server._TOOL_REGISTRY["_fake_read"] = lambda **kw: {"secret_token": "SENSITIVE-xyz"}
    try:
        spec = {
            "schema_version": 1, "name": "x", "description": "d",
            "steps": [
                {"id": "read",  "mcp": "rubrik", "tool": "_fake_read", "args": {}},
                {"id": "exfil", "mcp": "slack",  "tool": "post_message",
                 "args": {"text": "${read.secret_token}"}},
            ],
        }
        out = server._execute_workflow(spec, None)
        assert out["error"] == "cross_mcp_egress_blocked_by_policy"
        assert "completed" not in out
        assert "next_steps" not in out          # the exfil step was never assembled
        assert "SENSITIVE-xyz" not in json.dumps(out)   # no RSC data anywhere in the response
    finally:
        server._TOOL_REGISTRY.pop("_fake_read", None)


# --------------------------------------------------------------------------- #
# server.py enforcement — disabled write tool via workflow
# --------------------------------------------------------------------------- #

def test_disabled_write_tool_not_dispatchable_via_workflow(restore_policy):
    # rsc_assign_sla is not in the workflow dispatch registry unless enabled at
    # startup, so a workflow that targets it gets a clear policy message.
    assert "rsc_assign_sla" not in server._TOOL_REGISTRY
    spec = {
        "schema_version": 1, "name": "x", "description": "d",
        "steps": [{"id": "w", "mcp": "rubrik", "tool": "rsc_assign_sla", "args": {}}],
    }
    with pytest.raises(ValueError, match="disabled by policy"):
        server._execute_workflow(spec, None)


# --------------------------------------------------------------------------- #
# Parser robustness — real query names + adversarial argument shapes from the
# bundled rsc-client schema index (offline; no RSC credentials required).
# --------------------------------------------------------------------------- #

# Argument value shapes chosen to stress the tokenizer: a bare enum identifier,
# a nested input object (braces + identifiers inside the arg list), a list of
# input objects, and a string literal containing '}' and '(' (must be stripped
# before tokenizing or it would desync the brace/paren counters). None of these
# should ever leak into the extracted root-field list.
_ARG_VALUE_SHAPES = [
    "null",
    "SOME_ENUM",
    "{nested: null, more: DEEP_ENUM}",
    "[{x: null}, {y: OTHER_ENUM}]",
    '"a string with } and ( inside"',
]


def _render_args(arg_names) -> str:
    return ", ".join(
        f"{name}: {_ARG_VALUE_SHAPES[i % len(_ARG_VALUE_SHAPES)]}"
        for i, name in enumerate(arg_names)
    )


def test_parser_isolates_root_field_across_50_real_schema_queries():
    from rsc import describe_operation, list_queries

    names = list_queries()
    random.seed(1337)  # fixed seed -> reproducible in CI
    sample = random.sample(names, 50)

    for name in sample:
        arg_names = list((describe_operation(name, "query").get("args") or {}).keys())
        argblock = f"({_render_args(arg_names)})" if arg_names else ""

        # (a) plain, (b) with an adversarial arg block, (c) aliased — all must
        # extract exactly the single root field name and nothing from the args.
        assert server._root_query_fields(
            f"query {{ {name} {{ __typename }} }}"
        ) == [name], f"plain failed for {name}"
        assert server._root_query_fields(
            f"query {{ {name}{argblock} {{ __typename }} }}"
        ) == [name], f"args failed for {name}: {argblock}"
        assert server._root_query_fields(
            f"query {{ myAlias: {name}{argblock} {{ __typename }} }}"
        ) == [name], f"alias failed for {name}"

    # Two root fields with adversarial args on both are both isolated, in order.
    a, b = random.sample(names, 2)
    aa = f"({_render_args(list((describe_operation(a, 'query').get('args') or {}).keys()))})"
    bb = f"({_render_args(list((describe_operation(b, 'query').get('args') or {}).keys()))})"
    assert server._root_query_fields(
        f"query {{ {a}{aa} {{ __typename }} {b}{bb} {{ __typename }} }}"
    ) == [a, b]
