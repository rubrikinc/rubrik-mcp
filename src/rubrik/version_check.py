"""Compare the bundled rsc-client index against the connected RSC tenant.

The index that ships with rsc-client is built from one RSC schema date. RSC
tenants upgrade on a rolling schedule, so a given install can be behind its
tenant (newer operations are missing from discovery), ahead of it (indexed
operations may not exist on the tenant yet), or in sync.

At startup the server computes a ``SyncStatus`` once. Only when the index is
behind the tenant does it ask PyPI which rubrik-mcp releases exist, so it can
tell "a matching release is available" apart from "Rubrik hasn't released one
yet". The target release is the newest one whose schema date is on or before
the tenant's, never simply the latest: a release built for a newer RSC than the
tenant runs is not an upgrade for that tenant.

Set ``RUBRIK_MCP_NO_UPDATE_CHECK=1`` to skip the PyPI lookup.
"""

import json
import os
import re
import sys
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from importlib.metadata import PackageNotFoundError, distribution
from pathlib import Path

from rubrik import policy

PYPI_URL = "https://pypi.org/pypi/rubrik-mcp/json"
PYPI_TIMEOUT_SECONDS = 2.0
CACHE_FILE = "update-check.json"
CACHE_TTL = timedelta(hours=24)

IN_SYNC = "in_sync"
UPDATE_AVAILABLE = "update_available"   # index behind tenant, matching release published
AWAITING_RELEASE = "awaiting_release"   # index behind tenant, no newer release published yet
INDEX_AHEAD = "index_ahead"             # index newer than tenant
UNKNOWN = "unknown"                     # tenant date unavailable (e.g. RSC-P version format)

_RSC_DATE_RE = re.compile(r"v(\d{8})")
_RELEASE_RE = re.compile(r"^(\d+)\.(\d+)\.(\d{8})$")


@dataclass(frozen=True)
class SyncStatus:
    state: str
    index_date: str
    tenant_version: str = ""
    tenant_date: str | None = None
    target_version: str | None = None
    update_command: str | None = None

    @property
    def index_behind(self) -> bool:
        return self.state in (UPDATE_AVAILABLE, AWAITING_RELEASE)


def parse_tenant_date(deployment_version: str) -> str | None:
    """Return YYYYMMDD from an RSC deploymentVersion like ``v20260518-53``.

    RSC-P reports a different format (``2.x.x``), which yields None for now.
    """
    m = _RSC_DATE_RE.search(deployment_version or "")
    return m.group(1) if m else None


def _release_key(version: str) -> tuple[str, int, int] | None:
    """Sort key (schema date, major, minor) for a ``major.minor.YYYYMMDD`` release."""
    m = _RELEASE_RE.match(version)
    if not m:
        return None
    return (m.group(3), int(m.group(1)), int(m.group(2)))


def target_release(versions: list[str], tenant_date: str) -> str | None:
    """Newest release whose schema date is on or before the tenant's date."""
    candidates = [
        (key, v) for v in versions
        if (key := _release_key(v)) is not None and key[0] <= tenant_date
    ]
    return max(candidates)[1] if candidates else None


def _parse_pypi_releases(payload: dict) -> list[str]:
    """Release versions from PyPI's JSON API, skipping empty and fully yanked ones."""
    releases = payload.get("releases") or {}
    return [
        v for v, files in releases.items()
        if files and not all(f.get("yanked") for f in files)
    ]


def published_versions(now: datetime | None = None) -> list[str] | None:
    """rubrik-mcp releases on PyPI, cached for a day in the config dir.

    Returns None when the check is disabled or PyPI can't be reached and there
    is no cached answer. Never raises.
    """
    if os.environ.get("RUBRIK_MCP_NO_UPDATE_CHECK"):
        return None
    now = now or datetime.now(timezone.utc)
    cache_path = policy.rubrik_dir() / CACHE_FILE
    cached: dict | None = None
    try:
        cached = json.loads(cache_path.read_text())
        checked_at = datetime.fromisoformat(cached["checked_at"])
        if now - checked_at < CACHE_TTL:
            return list(cached["versions"])
    except Exception:
        pass

    try:
        req = urllib.request.Request(PYPI_URL, headers={"Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=PYPI_TIMEOUT_SECONDS) as resp:
            versions = _parse_pypi_releases(json.load(resp))
    except Exception as exc:
        print(f"[rubrik] update check skipped: {exc}", file=sys.stderr, flush=True)
        # A stale answer beats none: it can still name a matching release.
        return list(cached["versions"]) if cached and "versions" in cached else None

    try:
        cache_path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        cache_path.write_text(json.dumps({"checked_at": now.isoformat(), "versions": versions}))
    except Exception:
        pass
    return versions


def install_method() -> str:
    """How this server was installed: docker, source, uvx, uv-tool, or pip."""
    if Path("/.dockerenv").exists():
        return "docker"
    try:
        direct_url = distribution("rubrik-mcp").read_text("direct_url.json")
        if direct_url and json.loads(direct_url).get("dir_info", {}).get("editable"):
            return "source"
    except (PackageNotFoundError, ValueError):
        return "source"   # running from an uninstalled checkout
    parts = [p.lower() for p in Path(sys.prefix).parts]
    if "uv" in parts:
        # uvx runs from uv's cache (.../uv/archive-v0/<hash>); `uv tool install`
        # puts the env under .../uv/tools/rubrik-mcp.
        return "uv-tool" if "tools" in parts else "uvx"
    return "pip"


def update_command(version: str, method: str | None = None) -> str:
    """What the user should do to move to ``version``, for their install method."""
    method = method or install_method()
    if method == "uvx":
        step = (
            f"In your MCP client config, change the Rubrik MCP command from "
            f"`uvx rubrik-mcp` to `uvx rubrik-mcp@{version}`. Running uvx once by hand "
            f"does not change what the client launches."
        )
    elif method == "uv-tool":
        step = f"Run `uv tool install --force rubrik-mcp=={version}`."
    elif method == "docker":
        step = f"Rebuild the rubrik-mcp image from release {version} (see docs/docker.md)."
    elif method == "source":
        step = f"Update your rubrik-mcp checkout to release {version} and reinstall it."
    else:
        step = f"Run `{sys.executable} -m pip install rubrik-mcp=={version}`."
    return f"{step} Then restart your MCP client."


def compute_status(
    index_date: str,
    deployment_version: str,
    versions_fn=None,
) -> SyncStatus:
    """Classify the index against the tenant. Queries PyPI only when the index is behind."""
    tenant_date = parse_tenant_date(deployment_version)
    base = dict(index_date=index_date, tenant_version=deployment_version, tenant_date=tenant_date)
    if tenant_date is None:
        return SyncStatus(UNKNOWN, **base)
    if tenant_date == index_date:
        return SyncStatus(IN_SYNC, **base)
    if tenant_date < index_date:
        return SyncStatus(INDEX_AHEAD, **base)

    versions = (versions_fn or published_versions)() or []
    target = target_release(versions, tenant_date)
    if target and _release_key(target)[0] > index_date:
        return SyncStatus(
            UPDATE_AVAILABLE, **base,
            target_version=target, update_command=update_command(target),
        )
    return SyncStatus(AWAITING_RELEASE, **base)


def _fmt(date: str | None) -> str:
    return f"{date[:4]}-{date[4:6]}-{date[6:]}" if date else "unknown"


def instructions_notice(status: SyncStatus) -> str | None:
    """Text appended to the server instructions, only when the user has something to do."""
    if status.state != UPDATE_AVAILABLE:
        return None
    return (
        "\n\nUPDATE AVAILABLE: this Rubrik MCP's schema index is from "
        f"{_fmt(status.index_date)}, but the connected RSC tenant runs "
        f"{status.tenant_version}. rubrik-mcp {status.target_version} matches it. "
        "Operations added to RSC since the index date are missing from discovery. "
        "At a natural break, tell the user once that an update is available and how "
        f"to apply it: {status.update_command} Do not interrupt the user's current "
        "task for this, and do not run the update yourself."
    )


def index_behind_note(status: SyncStatus) -> str | None:
    """Explains a discovery miss when the index is older than the tenant."""
    if not status.index_behind:
        return None
    note = (
        f"This MCP's schema index is from {_fmt(status.index_date)}; the connected "
        f"tenant runs {status.tenant_version}. Operations added since "
        f"{_fmt(status.index_date)} are not in the index, so a missing operation may "
        "still exist on the tenant."
    )
    if status.state == UPDATE_AVAILABLE:
        note += f" A matching release is available. {status.update_command}"
    else:
        note += " No matching rubrik-mcp release is published yet."
    return note


def index_ahead_note(status: SyncStatus) -> str | None:
    """Explains an unknown-field error when the index is newer than the tenant."""
    if status.state != INDEX_AHEAD:
        return None
    return (
        f"This MCP's schema index is from {_fmt(status.index_date)}, newer than the "
        f"connected tenant ({status.tenant_version}). The operation or field may not "
        "exist on this tenant yet. Do not retry it; tell the user it is not available "
        "on their RSC version."
    )
