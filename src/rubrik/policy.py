"""Allow/deny gating policy for the Rubrik MCP server.

Loaded from ``~/.rubrik/mcp-policy.json``. This is an MCP-layer control that
complements RSC's server-side RBAC: RBAC bounds what the configured service
account *can* do; this policy bounds what the MCP server *will* do, independent
of the service account's role.

Fail-closed by design: a policy file that is present but malformed raises
:class:`PolicyError`, and the server refuses to start rather than fall back to a
permissive default. When no file exists, a secure-default template is seeded on
first run.

Gating surfaces:
  * ``writes_enabled``    — master switch; when false no write tool is registered.
  * ``write_tools``       — sparse per-tool override map; an omitted tool defaults
                            to enabled. Disabled tools are not registered at all.
  * ``queries``           — reads via ``rsc_execute_operation``; allow-by-default
                            with a denylist. Precedence: denied > allowed >
                            allow_by_default.
  * ``cross_mcp_egress``  — allowlist-only. A non-Rubrik MCP destination resolves
                            only if named in ``allowed``; there is no
                            allow_by_default, so deny is structural.
"""

from __future__ import annotations

import copy
import json
import os
import sys
from pathlib import Path
from typing import Any

POLICY_PATH = Path.home() / ".rubrik" / "mcp-policy.json"

# Curated write tools known to the server. Listed here so the seed template is
# self-documenting and an operator sees every write tool they can toggle.
WRITE_TOOL_NAMES = (
    "rsc_take_on_demand_snapshot",
    "rsc_assign_sla",
    "rsc_onboard_host",
)

_SEED_COMMENT = (
    "Rubrik MCP gating policy. Complements RSC RBAC (bounds what the MCP will do, "
    "not what the service account can do). Precedence for queries: "
    "denied > allowed > allow_by_default. cross_mcp_egress is allowlist-only "
    "(a destination resolves only if named in 'allowed'). Delete this file to "
    "regenerate defaults."
)

_DEFAULT_POLICY: dict[str, Any] = {
    "writes_enabled": True,
    "write_tools": {name: True for name in WRITE_TOOL_NAMES},
    "queries": {
        "allow_by_default": True,
        "allowed": [],
        "denied": [],
    },
    "cross_mcp_egress": {
        "allowed": [],
    },
}


class PolicyError(Exception):
    """Raised when the policy file is present but malformed. The server must refuse to start."""


def default_data() -> dict[str, Any]:
    """A fresh deep copy of the secure-default policy (no file access)."""
    return copy.deepcopy(_DEFAULT_POLICY)


class Policy:
    """A validated gating policy. Construct via :func:`load` (or directly in tests)."""

    def __init__(self, data: dict[str, Any]):
        self._data = data

    # --- writes ---------------------------------------------------------------
    @property
    def writes_enabled(self) -> bool:
        return bool(self._data["writes_enabled"])

    def write_tool_enabled(self, name: str) -> bool:
        if not self.writes_enabled:
            return False
        # Sparse override map: an omitted tool defaults to enabled.
        return bool(self._data["write_tools"].get(name, True))

    def any_writes_enabled(self) -> bool:
        """True if at least one write tool will be registered (writes are exposed).

        Used at startup to surface a write-enablement warning to the operator.
        """
        return self.writes_enabled and any(
            self.write_tool_enabled(n) for n in WRITE_TOOL_NAMES
        )

    # --- reads ----------------------------------------------------------------
    def query_allowed(self, name: str) -> bool:
        q = self._data["queries"]
        if name in q["denied"]:
            return False  # denied wins
        if name in q["allowed"]:
            return True
        return bool(q["allow_by_default"])

    # --- cross-MCP egress -----------------------------------------------------
    def cross_mcp_allowed(self, mcp_name: str) -> bool:
        # Allowlist-only: deny is structural, so a destination resolves only if
        # explicitly named. There is no allow_by_default to reopen egress.
        return mcp_name in self._data["cross_mcp_egress"]["allowed"]

    # --- diagnostics ----------------------------------------------------------
    def summary(self) -> str:
        disabled = [n for n in WRITE_TOOL_NAMES if not self.write_tool_enabled(n)]
        q = self._data["queries"]
        allowed_egress = self._data["cross_mcp_egress"]["allowed"]
        return "; ".join([
            f"writes={'on' if self.writes_enabled else 'OFF'}",
            f"write_tools_disabled={disabled or 'none'}",
            (
                f"queries={'allow' if q['allow_by_default'] else 'deny'}-by-default"
                f" (+{len(q['denied'])} denied)"
            ),
            f"cross_mcp_egress_allowed={allowed_egress or 'none'}",
        ])


def _merge(base: dict[str, Any], override: dict[str, Any]) -> dict[str, Any]:
    """Shallow-merge ``override`` onto ``base`` one level into nested dicts, so an
    operator can write a partial policy and still get defaults for omitted keys."""
    out = copy.deepcopy(base)
    for k, v in override.items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            merged = copy.deepcopy(out[k])
            merged.update(v)
            out[k] = merged
        else:
            out[k] = v
    return out


def _validate(data: dict[str, Any]) -> None:
    if not isinstance(data.get("writes_enabled"), bool):
        raise PolicyError("'writes_enabled' must be a boolean")

    wt = data.get("write_tools")
    if not isinstance(wt, dict) or not all(isinstance(v, bool) for v in wt.values()):
        raise PolicyError("'write_tools' must be an object mapping tool_name -> boolean")

    q = data.get("queries")
    if not isinstance(q, dict):
        raise PolicyError("'queries' must be an object")
    if not isinstance(q.get("allow_by_default"), bool):
        raise PolicyError("'queries.allow_by_default' must be a boolean")
    for key in ("allowed", "denied"):
        val = q.get(key)
        if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
            raise PolicyError(f"'queries.{key}' must be a list of strings")

    ce = data.get("cross_mcp_egress")
    if not isinstance(ce, dict):
        raise PolicyError("'cross_mcp_egress' must be an object")
    allowed = ce.get("allowed")
    if not isinstance(allowed, list) or not all(isinstance(x, str) for x in allowed):
        raise PolicyError("'cross_mcp_egress.allowed' must be a list of strings")


def _seed(path: Path) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    seed = {"_comment": _SEED_COMMENT, **default_data()}
    # Create with 0o600 atomically: opening with the mode up front avoids the
    # TOCTOU window a write-then-chmod leaves, during which another process
    # could read the file at the default umask.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        f.write(json.dumps(seed, indent=2) + "\n")
    print(f"[rubrik] seeded default gating policy at {path}", file=sys.stderr, flush=True)


def load(path: Path = POLICY_PATH, *, seed_if_absent: bool = True) -> Policy:
    """Load and validate the gating policy.

    Absent file -> seed the secure-default template (unless ``seed_if_absent`` is
    False) and return defaults. Present-but-malformed -> raise :class:`PolicyError`.
    """
    if not path.exists():
        if seed_if_absent:
            _seed(path)
        return Policy(default_data())

    try:
        raw = json.loads(path.read_text())
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise PolicyError(f"{path} is not valid JSON: {exc}") from exc
    if not isinstance(raw, dict):
        raise PolicyError("policy root must be a JSON object")

    merged = _merge(_DEFAULT_POLICY, raw)
    _validate(merged)
    return Policy(merged)
