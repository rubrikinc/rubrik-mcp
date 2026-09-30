# Rubrik MCP

An MCP server that connects AI assistants to the [Rubrik Security Cloud](https://www.rubrik.com/) GraphQL API. It's built for Rubrik admins and teams automating against Rubrik, and runs locally (on your own workstation or on an agent's server) alongside the AI assistant that calls it.

<!-- Ownership marker for the MCP Registry. It verifies that this PyPI package
     belongs to the server named in server.json by looking for this string in
     the published package description. Must match server.json's `name` exactly,
     and must not be followed by punctuation. -->
<!-- mcp-name: io.github.rubrikinc/rubrik-mcp -->

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

Raw GraphQL execution is read-only. If you ask for a write operation not covered by a built-in tool, the server returns the attempted mutation and the agent generates a runnable code sample. A small number of write operations are available as dedicated built-in tools: on-demand snapshots (`rsc_take_on_demand_snapshot`), host onboarding (`rsc_onboard_host`), and SLA assignment (`rsc_assign_sla`). **These are disabled by default** — set `"writes_enabled": true` in the [gating policy](https://github.com/rubrikinc/rubrik-mcp/blob/main/docs/advanced.md#gating-policy) to expose them. For everything else, the generated code approach gives you a runnable script with full control.

> [!WARNING]
> **Write tools act on your Rubrik environment, and the LLM driving the MCP decides when to call them.** Any model can misread instructions or be influenced by untrusted data it reads (prompt injection) and invoke a write tool you did not intend — for example an SLA change via `rsc_assign_sla` that leaves data unprotected. As more write tools are added, this surface grows. They are disabled by default for that reason; enabling them is an explicit choice. The durable boundary is a **least-privilege, read-only service account**, which cannot perform any write operation regardless of which model you use or how the agent behaves. See [Service account role recommendations](#service-account-role-recommendations), and enable **Quorum Authorization** for destructive operations.

### Built-in tools

**Discovery** — no credentials required

| Tool | What it does |
|------|-------------|
| `rsc_search_schema` | Find the right query or mutation by keyword, field meaning, or type vocabulary in one call |
| `rsc_describe_operation_full` | Argument signature with all input/enum types expanded inline |
| `rsc_describe_type` | Fields and values for a GraphQL type |

**Execution** — service account required

| Tool | What it does |
|------|-------------|
| `rsc_execute_operation` | Run any raw GraphQL query (mutations generate code instead) |
| `rsc_get_workloads` | Workloads with protection status, compliance, and backup history |
| `rsc_get_events` | Recent events and activity, always time-scoped |
| `rsc_get_clusters` | Rubrik clusters registered in RSC, with status, version, capacity, and runway |
| `rsc_get_sla_domains` | SLA Domains with base frequency, retention lock, archival, and replication settings |
| `rsc_search_help` | Search KB articles, product docs, and known issues by keyword |
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

### Hardened install (optional)

The commands above install the pinned dependency set. For environments that require **install-time hash verification** — each package checked against a known-good cryptographic hash before it is installed — a hashed `requirements.txt` is published with each release. Install the verified dependency set first, then the package itself:

```bash
pip install --require-hashes -r requirements.txt
pip install --no-deps rubrik-mcp
```

`requirements.txt` is generated from the locked, hash-pinned dependency set (`uv export`); `--require-hashes` makes pip refuse any package whose hash does not match, and `--no-deps` on the second step keeps the verified set untouched. This path is optional — the standard install above is sufficient for most users.

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

The AI calls `rsc_save_workflow`, which writes a JSON file to the MCP config directory's `workflows/` folder — `~/.config/rubrik-mcp/workflows/` by default, or under `$RUBRIK_MCP_CONFIG_DIR` when set (see [docs/docker.md](https://github.com/rubrikinc/rubrik-mcp/blob/main/docs/docker.md) for the containerized case). On the next restart, that workflow is registered as a named MCP tool — a single call instead of multi-step schema discovery. Repeated operations use fewer tokens and respond faster.

Workflow files are plain JSON. Open them in any editor, adjust the query, change the defaults, or share them with your team.

Community-contributed workflows (threat feed management, SLA operations, and more) are available in the [rubrik-community](https://github.com/rubrikinc/rubrik-community) repository. Copy any JSON file into the config directory's `workflows/` folder (`~/.config/rubrik-mcp/workflows/` by default, or under `$RUBRIK_MCP_CONFIG_DIR`) and restart your MCP client to install it.

---

## Further reading

For the full built-in tools reference, architecture diagram, the local gating policy (`~/.config/rubrik-mcp/mcp-policy.json`, relocatable via `$RUBRIK_MCP_CONFIG_DIR`), the audit log (`mcp-audit.log`, in the same config directory), upgrade notes for config previously kept in `~/.rubrik`, and development setup, see [docs/advanced.md](https://github.com/rubrikinc/rubrik-mcp/blob/main/docs/advanced.md). To run the server in a container, see [docs/docker.md](https://github.com/rubrikinc/rubrik-mcp/blob/main/docs/docker.md).
