# adapters/ — Phase 4 ✅ (per-agent instruction files)

Thin instruction files (≈20 lines, no logic) that tell each agent to run vulngate
before declaring work deployment-ready — scan, read `findings.json`, and use the
MCP tools if the server is connected. Copy the one(s) for your agent into your repo.

| Agent | Template | Install location |
|---|---|---|
| Claude Code | [`SKILL.md`](SKILL.md) | `.claude/skills/vulngate-security-gate/SKILL.md` |
| Codex + cross-agent | [`AGENTS.md`](AGENTS.md) | repo root as `AGENTS.md` (append if you already have one) |
| Cursor | [`cursor.mdc`](cursor.mdc) | `.cursor/rules/vulngate.mdc` |
| Windsurf | [`AGENTS.md`](AGENTS.md) | Windsurf reads `AGENTS.md` / repo rules — use the AGENTS.md content |

They're intentionally identical in intent, differing only in each agent's file
format. All of them defer to the [CLI](../README.md) and the
[MCP server](../mcp-server/) — no scan logic is duplicated.

This repo dogfoods its own gate: see the root [`AGENTS.md`](../AGENTS.md).

> The enforcement point is still **CI** (the [Action](../action/)). Adapters are
> for in-IDE convenience — an agent can ignore an instruction file, but it can't
> ignore a failing merge check.
