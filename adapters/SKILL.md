---
name: vulngate-security-gate
description: Find and fix security vulnerabilities (SAST, hard-coded secrets, dependency CVEs) with vulngate before declaring code deployment-ready. Use before finishing any task that changed code, or when the user says to check security, ship, or deploy.
---

# vulngate security gate

Before you tell the user a change is done or ready to deploy, run vulngate and resolve everything at or above `high`.

1. **Scan.** If the vulngate MCP server is connected, call `scan_repo`; otherwise run `vulngate scan .`. Exit code `1` = findings at/above the threshold, `2` = tool error.
2. **Read** the normalized results from `findings.json` (fields: `severity`, `file`, `line`, `plain_summary`, `remediation_hint`).
3. **Explain + fix.** For each finding at/above `high`: if the MCP server is available use `explain_finding` then `suggest_patch`; otherwise use `plain_summary` and `remediation_hint`. Explain the risk to the user in plain English and propose a **minimal** fix.
4. **Show the diff before applying** any security fix. Never commit a secret — rotate it and load it from an environment variable.
5. **Verify.** After applying a fix, confirm it landed: with the MCP server, call `verify_fix` (re-scans and only reports `fixed` when the owning scanner actually ran); otherwise re-run `vulngate scan .` and check the finding's `id` is gone. A finding vanishing because a scanner didn't run is **not** a fix.

Not installed? Tell the user: `pip install "vulngate[scanners]"` (and `brew install gitleaks` for secret scanning). vulngate is deterministic and free — it scans the code, not the agent.
