<!-- Community-maintained, no SLA. Small, focused PRs get reviewed fastest. -->

## What this changes

<!-- One or two sentences. Link the issue if there is one. -->

## Why

<!-- What was wrong or missing. -->

## How it was proved

<!-- For a fix: what you did to confirm it actually fixes the thing. -->
<!-- For a test: how you made it fail on purpose. A test that can't fail isn't a test. -->

## Checklist

- [ ] `pytest -q` passes
- [ ] `vulngate scan test-fixtures/vulnerable-sample` still exits `1` (detection didn't regress)
- [ ] No secret values, source snippets, or absolute paths can reach `findings.json`
- [ ] The core stays dependency-free and makes no LLM calls
- [ ] Scan logic lives in the CLI core only — the Action, MCP server and adapters stay thin wrappers
- [ ] Docs updated if behaviour or flags changed
