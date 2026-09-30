# Rubrik MCP

## Project layout

```
src/rubrik/
  server.py     # FastMCP server — all tools defined here
  __init__.py
```

All tools are defined in `server.py`. There is no plugin system — add a new tool by decorating a function with `@mcp.tool()`.

## Development setup

```bash
git clone https://github.com/rubrikinc/rubrik.git

cd rubrik
python3 -m venv .venv && source .venv/bin/activate
pip install -e .
```

To develop against a local `rsc-client` checkout instead of PyPI:

```bash
git clone https://github.com/rubrikinc/rubrik-security-cloud-python-graphql-client.git
pip install -e ../rubrik-security-cloud-python-graphql-client
```

## Running locally

```bash
rubrik          # stdio mode (default)
```

Set credentials before running (execution tools only — discovery tools need no auth):

```bash
export RSC_SERVICE_ACCOUNT_FILE=/path/to/service_account.json
```

## Tool categories

| Category | Auth required | Where defined |
|----------|--------------|---------------|
| Discovery | No | `server.py` — `rsc_search_schema`, `rsc_describe_*` |
| Execution | Yes | `server.py` — `rsc_execute_operation`, `rsc_get_workloads`, `rsc_get_events`, etc. |
| Workflows | Yes | `server.py` — `rsc_save_workflow`, `rsc_list_workflows`, `rsc_delete_workflow` |

User-defined workflows are persisted to `~/.config/rubrik-mcp/workflows/` as JSON. On startup, the server loads every JSON file in that directory and registers it as a named MCP tool.

## Write operations

`rsc_execute_operation` rejects raw mutations. Write operations are only available through vetted built-in tools (currently `rsc_take_on_demand_snapshot`). When adding a new built-in mutation tool, keep the surface area small and the mutation string hardcoded — never construct mutation text from caller-controlled input.

## Adding a tool

When a user asks to "create a tool", **default to a user-level workflow** saved via `rsc_save_workflow` to `~/.config/rubrik-mcp/workflows/`. Do NOT edit `server.py` unless the user explicitly asks for a built-in tool, or the required behavior is impossible in the workflow engine (e.g. looping over a dynamic result set).

To add a built-in tool to `server.py`:
1. Add a `@mcp.tool()` decorated function in `server.py`
2. Include a docstring — the MCP client uses it as the tool description
3. Use `RSCClient` (from `rsc`) for any live API calls; use the index functions (`describe_operation`, `search_operations`, etc.) for offline discovery

## Versioning

rubrik-mcp uses `major.minor.YYYYMMDD` versioning, where `YYYYMMDD` is the schema date of the pinned `rsc-client` release — not the release date of rubrik-mcp itself. Never set the date portion to today just to cut a release; it must match the schema version the package was built against. Bump `major` or `minor` for API/feature changes; update the date only when pinning a new `rsc-client` schema version.

Example: `0.6.20260817` means feature level 0.6, built against the August 17 2026 RSC schema.

## rsc-client dependency

Discovery tools read from pre-generated JSON indexes that ship with `rsc-client` (`mcp_index.json`, `mcp_types.json`). These are regenerated from the RSC GraphQL SDL in the `rsc-client` CI pipeline whenever the schema updates. No network access is needed for discovery.

`RSCClient` handles OAuth2 token acquisition and caching for live API calls.

## Testing

There is no test suite yet. To smoke-test a new tool, run the server and invoke the tool via your MCP client, or use the MCP inspector:

```bash
npx @modelcontextprotocol/inspector rubrik
```
