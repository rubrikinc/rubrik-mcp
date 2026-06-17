"""
Integration tests for rubrik.server — require a live RSC tenant (READ-ONLY).

Self-skipping: runs only when RSC_SERVICE_ACCOUNT_FILE points at a readable SA
credential. All tests here are read-only and safe against any tenant.

Write-tool tests (mutating) are tracked under a separate ticket — the mock-vs-live
approach is still being decided. See ~/Dev/rubrik-mcp-write-tests-draft.py.

Usage:
    RSC_SERVICE_ACCOUNT_FILE=~/.config/rsc/sa.json pytest -m integration
"""

import os
import pytest


def _have_sa() -> bool:
    sa = os.environ.get("RSC_SERVICE_ACCOUNT_FILE", "")
    return bool(sa and os.path.exists(os.path.expanduser(sa)))


integration = pytest.mark.skipif(
    not _have_sa(),
    reason="RSC_SERVICE_ACCOUNT_FILE not set / file missing — skipping live-RSC tests",
)

pytestmark = pytest.mark.integration


@integration
def test_get_workloads_returns_list():
    from rubrik.server import rsc_get_workloads
    result = rsc_get_workloads(limit=5)
    assert isinstance(result, list)
    if result:
        item = result[0]
        assert "fid" in item or "id" in item
        assert "objectType" in item


@integration
def test_get_events_returns_list():
    from rubrik.server import rsc_get_events
    assert isinstance(rsc_get_events(last_hours=24, limit=5), list)


@integration
def test_execute_operation_query_returns_data():
    from rubrik.server import rsc_execute_operation
    result = rsc_execute_operation("query { accountId }")
    assert result.get("error") != "mutation_blocked"
    assert result.get("data", {}).get("accountId")


@integration
def test_execute_operation_blocks_mutation_live():
    from rubrik.server import rsc_execute_operation
    result = rsc_execute_operation(
        "mutation TakeSnapshot($i: TakeOnDemandSnapshotInput!) "
        "{ takeOnDemandSnapshot(input: $i) { taskchainUuids { taskchainUuid } } }"
    )
    assert result["error"] == "mutation_blocked"


@integration
def test_deployment_version_reachable():
    """Backs the startup schema-sync check — confirm the version query works."""
    from rubrik.server import RSCClient
    raw = RSCClient().execute("query { deploymentVersion }")
    assert raw is not None


@integration
def test_wait_for_job_unknown_id_errors_cleanly():
    """An unknown job ID must surface a clean error (RuntimeError from
    _data_or_raise), NOT crash with TypeError/AttributeError."""
    from rubrik.server import rsc_wait_for_job
    try:
        result = rsc_wait_for_job(
            job_id="00000000-0000-0000-0000-000000000000",
            object_type="AzureNativeVm",
            timeout=10,
            poll_interval=5,
        )
        assert isinstance(result, dict)
    except (AttributeError, TypeError) as e:
        pytest.fail(f"rsc_wait_for_job crashed instead of erroring cleanly: {type(e).__name__}: {e}")
    except Exception:
        pass  # a clean RuntimeError / RSC error is acceptable
