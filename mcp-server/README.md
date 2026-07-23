# mcp-server/ — Phase 3 (planned)

The **flagship layer for the vibe-coder loop**: a local stdio MCP server (no
hosting) that shells out to the CLI and lets your own agent understand and fix
findings on your subscription. Nothing here yet.

Planned tools:
- `scan_repo(path, fail_on?)` → normalized findings JSON.
- `explain_finding(finding_id)` → full context: the code snippet around
  `file:line` (read **live** from the working tree, never persisted to
  findings.json), rule docs link, remediation hint — structured so the host
  agent does the reasoning.
- `suggest_patch(finding_id)` → the finding plus surrounding code context,
  formatted for the host agent to draft a fix. The tool never writes code or
  auto-applies anything — human/agent approval stays outside our boundary.

Read-only against the repo except for writing `findings.json`. Tool
descriptions are written carefully — they are prompts.
