# Contributing to vulngate

Thanks for helping! vulngate is **community-maintained with no SLA**. There's no
guaranteed response time — but issues and PRs are genuinely welcome, and peer
help lives in **GitHub Discussions**.

## Ground rules

- Be kind — see [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- vulngate must not itself ship vulnerabilities: Dependabot runs on this repo
  and CI lints/tests every change.
- Keep the **core dependency-free** (stdlib only). Scanners are external tools
  we shell out to, never imported.

## Good first contributions

1. **Plain-English knowledge pack** — add or improve an entry in
   [`vulngate/knowledge.py`](vulngate/knowledge.py). Map a CWE or rule to one
   clear sentence a non-expert understands. Self-contained, high-impact.
2. **A scanner adapter** — see below.

## Dev setup

```bash
git clone https://github.com/cisoventures/vulngate && cd vulngate
pip install -e ".[dev,scanners]"
pytest -q                                   # unit tests (no network)
vulngate scan test-fixtures/vulnerable-sample   # end-to-end; should exit 1
```

## Adding a scanner adapter

1. Create `vulngate/scanners/<tool>_scanner.py` exposing
   `run(root: Path, det) -> ScanOutput`.
2. Use the helpers in `scanners/base.py` (`resolve_cmd`, `run_cmd`,
   `not_applicable`/`unavailable`/`disabled`, `errored`, `completed`,
   `rel_posix`, `normalize_cwes`). Return `not_applicable(...)` when the repo has
   nothing for the tool to scan, `unavailable(...)` when the tool isn't installed
   — the distinction drives `scan.status` (a missing-but-applicable scanner is a
   coverage gap → `partial`, not silently ignored).
3. Map the tool's native severities onto `critical|high|medium|low`.
4. Build each `Finding` via `schema.fingerprint(...)` for a stable id. **Never**
   put secret values or source snippets into a finding — that's a hard rule.
5. Register it in the `SCANNERS` dict in `cli.py`. That's the only wiring.
6. Add a fixture case under `test-fixtures/` if it exercises a new pattern.

## Design invariants (please preserve)

- One CLI core; the Action/MCP/adapters are thin wrappers — never duplicate
  scan logic.
- The core makes **no LLM calls**. Inference is bring-your-own.
- Graceful degradation always: a missing/broken scanner warns and skips.
- `findings.json` is safe to share: no secrets, no snippets, no absolute paths.
