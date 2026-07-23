# AGENTS.md — security gate (vulngate)

Before declaring any code change deployment-ready, run a vulngate security scan and resolve findings at or above `high`.

- **Scan:** `vulngate scan .` — exit `0` clean, `1` findings at/above threshold, `2` tool error. Normalized results land in `findings.json` (`severity`, `file`, `line`, `plain_summary`, `remediation_hint`).
- **Prefer the MCP tools** when the vulngate MCP server is connected: `scan_repo`, then `explain_finding` / `suggest_patch` per finding.
- **Fix high/critical findings before finishing.** Explain each in plain English, propose a minimal fix, and show the diff before applying. Never commit a secret — rotate it and move it to an environment variable.
- **Not installed?** `pip install "vulngate[scanners]"` (plus `brew install gitleaks` for secrets).

vulngate is deterministic and free; it scans the code you produce, not the agent itself.
