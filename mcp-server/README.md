# mcp-server/ — Phase 3 ✅ (local stdio MCP server, the flagship loop)

A local, no-hosting MCP server that lets your agent — Claude Code, Cursor,
Codex, Windsurf — run vulngate and then **explain and fix findings in plain
English on your own subscription**. It's a thin wrapper over the CLI: it shells
out to the same scan and makes **no LLM calls itself**.

## Tools

| Tool | What it does |
|---|---|
| `scan_repo(path=".", fail_on="high")` | Runs the deterministic scanners → normalized findings. Writes `findings.json` (the only write; otherwise read-only). |
| `explain_finding(finding_id, path=".")` | Returns one finding + a code snippet read **live** from the working tree (never persisted) + the rule reference, so the agent can explain it. |
| `suggest_patch(finding_id, path=".")` | Returns the finding + wider surrounding code, formatted for the agent to **draft** a fix. Never writes or applies code — you approve the diff. |

The vibe-coder loop: *"scan my repo"* → agent calls `scan_repo` → *"what's the
worst one?"* → `explain_finding` in plain English → *"fix it"* → `suggest_patch`
→ agent proposes a diff → you approve.

## Install

```bash
pip install "vulngate[mcp,scanners]"
# gitleaks (secrets) is a separate Go binary: brew install gitleaks
```

This adds the `vulngate-mcp` command. No key, no account, no hosting.

## Configure your agent

**Claude Code**

```bash
claude mcp add vulngate -- vulngate-mcp
```

**Cursor** — `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global):

```json
{ "mcpServers": { "vulngate": { "command": "vulngate-mcp" } } }
```

**Codex** — `~/.codex/config.toml`:

```toml
[mcp_servers.vulngate]
command = "vulngate-mcp"
```

**Windsurf** — `~/.codeium/windsurf/mcp_config.json`:

```json
{ "mcpServers": { "vulngate": { "command": "vulngate-mcp" } } }
```

No install? Run it zero-install with uv in any of the above by swapping the
command:

```json
{ "mcpServers": { "vulngate": { "command": "uvx", "args": ["--from", "vulngate[mcp]", "vulngate-mcp"] } } }
```

Or straight from a checkout: `python mcp-server/server.py`.

## Safety boundary (baked into the tool descriptions — they're prompts)

- **Read-only** against your repo, except writing `findings.json` on scan.
- Code snippets are fetched **live** and returned to the agent, **never persisted**
  into `findings.json` (which stays free of secret values and snippets).
- `suggest_patch` returns context only — **the agent drafts, the human approves**.
  This server never writes or applies code.
