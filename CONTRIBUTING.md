# Contributing to vulngate

Thanks for helping! vulngate is **community-maintained with no SLA**. There's no
guaranteed response time — but issues and PRs are genuinely welcome. Questions
and bugs go in [Issues](https://github.com/cisoventures/vulngate/issues); a
**security flaw in vulngate itself** goes through
[private reporting](https://github.com/cisoventures/vulngate/security/advisories/new),
never a public issue — see [SECURITY.md](SECURITY.md).

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

CI runs the suite on Python **3.11, 3.12 and 3.13**, plus the end-to-end scan of
the deliberately-vulnerable fixture. A change that stops that fixture exiting `1`
is a detection regression, not a style question.

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
- **A new test has to be able to fail.** Break the thing it covers on purpose,
  watch it go red, then restore. A test that agrees with the implementation
  rather than with reality proves nothing.
- The core makes **no LLM calls**. Inference is bring-your-own.
- Graceful degradation always: a missing/broken scanner warns and skips.
- `findings.json` is safe to share: no secrets, no snippets, no absolute paths.
