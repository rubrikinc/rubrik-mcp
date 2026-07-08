# Rubrik MCP

An MCP server that connects AI assistants to the [Rubrik Security Cloud](https://www.rubrik.com/) GraphQL API.

---

## What you can do

### Discovery

The MCP ships with a pre-built index of the entire RSC GraphQL API. The discovery tools let the AI agent explore that index — searching operations, inspecting full argument signatures, tracing input and return types — to find exactly the right operation and field shape for any request. This produces precise, well-formed GraphQL on the first try.

Discovery tools require no RSC credentials and work entirely offline. This makes them useful on their own: if you're evaluating the API, prototyping an integration, or building automation before you have production credentials, you can start immediately.

```
> "What operations are available for SLA management?"
> "Show me the full argument shape for the assignSla mutation."
> "Generate Python code to assign an SLA domain to a list of workload IDs."
```

Because the agent understands both queries and mutations from the schema index, it can generate runnable Python code for any write operation — without ever connecting to RSC.

### Execution

With an RSC service account, the agent can run live GraphQL queries against your environment:

- List workloads with protection status, compliance state, and backup history
- Retrieve recent events and failures
- Trigger on-demand snapshots and poll until they complete
- Register hosts and assign SLA domains

Raw GraphQL execution is read-only. If you ask for a write operation not covered by a built-in tool, the server returns the attempted mutation and the agent generates a runnable code sample. A small number of write operations are available as dedicated built-in tools: on-demand snapshots (`rsc_take_on_demand_snapshot`), host onboarding (`rsc_onboard_host`), and SLA assignment (`rsc_assign_sla`). For everything else, the generated code approach gives you a runnable script with full control.

### Built-in tools

**Discovery** — no credentials required

| Tool | What it does |
|------|-------------|
| `rsc_search_operations` | Find queries and mutations by keyword |
| `rsc_describe_operation` | Argument signature for a named operation |
| `rsc_describe_operation_full` | Signature with all input types expanded inline |
| `rsc_describe_type` | Fields and values for a GraphQL type |
| `rsc_search_fields` | Search field names and descriptions across all types |
| `rsc_list_queries` | All query names |
| `rsc_list_mutations` | All mutation names |
| `rsc_list_types` | All type names |
| `rsc_list_types_matching` | Filter type names by substring |

**Execution** — service account required

| Tool | What it does |
|------|-------------|
| `rsc_execute_operation` | Run any raw GraphQL query (mutations generate code instead) |
| `rsc_get_workloads` | Workloads with protection status, compliance, and backup history |
| `rsc_get_events` | Recent events and activity, always time-scoped |
| `rsc_take_on_demand_snapshot` | Trigger a backup for a workload and return the job ID |
| `rsc_wait_for_job` | Poll a job until completion |
| `rsc_onboard_host` | Register a physical or virtual host |
| `rsc_assign_sla` | Assign, unassign, or set do-not-protect on workloads |

**Workflow management** — service account required

| Tool | What it does |
|------|-------------|
| `rsc_save_workflow` | Save a conversation flow as a named reusable tool |
| `rsc_list_workflows` | List all saved workflows |
| `rsc_delete_workflow` | Remove a saved workflow |

### Tool creation

After the agent has done the discovery work to answer a question, you can save that entire flow as a named MCP tool:

> "Save this as a workflow so I can reuse it."

On the next restart, that tool appears alongside the built-in tools — a single call instead of multi-step schema discovery. Repeated operations use fewer tokens and respond faster. Workflow files are plain JSON you can edit, version-control, and share with your team.

---

## Installation

### Prerequisites

- Python 3.10 or later
- A Rubrik Security Cloud account with a service account (for execution tools only)

### Install via agent prompt

If you're using Claude Code, paste this into the chat and the agent will handle the rest:

> "Install the Rubrik MCP from `https://github.com/rubrikinc/rubrik-mcp` and add it to my Claude Code MCP configuration. My RSC service account JSON is at `~/.rsc/service_account.json`."

For Claude Desktop:

> "Install the Rubrik MCP from `https://github.com/rubrikinc/rubrik-mcp` and add it to my Claude Desktop config. My RSC service account JSON is at `~/.rsc/service_account.json`."

### Install manually

**Using pip:**

```bash
pip install git+https://github.com/rubrikinc/rubrik-mcp.git
```

**Using uv:**

```bash
uv pip install git+https://github.com/rubrikinc/rubrik-mcp.git
```

Note the full path to the installed command — you will need it for client configuration:

```bash
which rubrik
# example: /Users/you/.venv/bin/rubrik
```

### Configure your MCP client

**Claude Code:**

```bash
claude mcp add rubrik -- /path/to/rubrik -e RSC_SERVICE_ACCOUNT_FILE=/path/to/service_account.json
```

Verify it's registered:

```bash
claude mcp list
```

**Claude Desktop** — edit `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `%APPDATA%\Claude\claude_desktop_config.json` (Windows):

```json
{
  "mcpServers": {
    "rubrik": {
      "command": "/path/to/rubrik",
      "env": {
        "RSC_SERVICE_ACCOUNT_FILE": "/path/to/service_account.json"
      }
    }
  }
}
```

**Other MCP clients (generic stdio):**

```json
{
  "name": "rubrik",
  "transport": "stdio",
  "command": "/path/to/rubrik",
  "env": {
    "RSC_SERVICE_ACCOUNT_FILE": "/path/to/service_account.json"
  }
}
```

---

## Service account setup

Create a service account in RSC at **Settings > Users and Roles > Service Accounts**. Download the JSON credential file when prompted — RSC will not show the secret again.

The credential file looks like this:

```json
{
  "client_id": "client|...",
  "client_secret": "...",
  "access_token_uri": "https://<your-rsc-domain>/api/client_token"
}
```

Provide it to the MCP server using one of three methods (checked in this order):

**Option A — Service account JSON file (recommended)**

```bash
export RSC_SERVICE_ACCOUNT_FILE=/path/to/service_account.json
```

**Option B — Individual environment variables**

```bash
export RSC_URL=https://<your-rsc-domain>
export RSC_CLIENT_ID=client|...
export RSC_CLIENT_SECRET=...
```

**Option C — Config file at `~/.rsc/config.json`**

```json
{
  "client_id": "client|...",
  "client_secret": "...",
  "access_token_uri": "https://<your-rsc-domain>/api/client_token"
}
```

---

## Service account role recommendations

The role you assign to the service account determines what the MCP server can access. Assign only what your workflows actually need.

**For monitoring, reporting, and auditing** — assign a read-only role. This covers workload listing, compliance status, event history, and backup reporting. A read-only role cannot modify SLA assignments, trigger snapshots, or change any configuration. This is the right starting point for most users.

**For DevOps automation** — assign a role with the specific permissions your automation requires. Common additions: SLA management permissions (to assign or modify SLA domains) and on-demand backup permissions (to trigger snapshots). Do not grant cluster admin or global admin unless the workflow explicitly requires it.

**General guidance:**

- Create a dedicated role for the MCP service account rather than reusing an existing admin role. Name it clearly (e.g. "MCP Read-Only" or "MCP DevOps").
- Configure roles at **Settings > Users and Roles > Roles**. Rubrik's permission model is hierarchical — scope roles to specific clusters or workload types where possible rather than granting global access.
- For destructive operations (snapshot deletion, SLA policy removal, cluster configuration), enable Quorum Authorization at **Settings > Security > Quorum Authorization**. This requires a second authorized user to approve the operation before it executes, even when the service account has the necessary permissions.
- Restrict which IPs can authenticate using the RSC IP allowlist at **Settings > Security > IP Allowlist**. Add only the IP or CIDR range of the machine running the MCP server.
- Rotate client secrets on a schedule (monthly at minimum). Secrets do not expire by default. Use `chmod 600` on any file containing a `client_secret`.
- All API activity is recorded in RSC audit logs at **Reports > Audit Logs**. Review periodically.

---

## Saving your own tools

When you find yourself asking the same question repeatedly, save it:

> "Save this as a workflow so I can reuse it."

The AI calls `rsc_save_workflow`, which writes a JSON file to `~/.rubrik/workflows/`. On the next restart, that workflow is registered as a named MCP tool — a single call instead of multi-step schema discovery. Repeated operations use fewer tokens and respond faster.

Workflow files are plain JSON. Open them in any editor, adjust the query, change the defaults, or share them with your team.

**Starter workflows** (available on first run):

| Workflow | Description |
|----------|-------------|
| `rsc_snapshot_and_wait` | Take an on-demand snapshot for a cloud-native workload and poll until it completes |
| `rsc_protection_gaps` | Out-of-compliance workloads and recent backup failures in one combined call |
| `rsc_find_and_snapshot` | Find a workload by name, snapshot it, and wait for completion |

Additional community-contributed workflows — threat feed management, SLA operations, and more — are available in the [rubrik-community](https://github.com/rubrikinc/rubrik-community) repository. Copy any JSON file into `~/.rubrik/workflows/` and restart your MCP client to install it.

---

## Further reading

For the full built-in tools reference, architecture diagram, the local gating policy (`~/.rubrik/policy.json`), and development setup, see [docs/advanced.md](docs/advanced.md).
