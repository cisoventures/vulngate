# adapters/ — Phase 4 (planned)

Thin per-agent instruction files (≈20 lines each, no logic) that point agents at
the CLI/MCP. Nothing here yet.

Planned:
- `SKILL.md` (Claude), `.cursor/rules` (Cursor), `AGENTS.md` (Codex and the
  emerging cross-agent convention — one file may cover several agents).
- Each tells the agent: run the scan before declaring work deployment-ready,
  read `findings.json`, and use the MCP tools if available.

Distribution (all free): MCP registries, awesome-lists, Show HN, r/programming,
and this repo as the canonical landing page.
