# Distribution (Phase 4 go-to-market)

All free channels. The repo itself is the canonical landing page.

| Channel | Status | Notes |
|---|---|---|
| **GitHub repo** | ✅ live | https://github.com/cisoventures/vulngate (public, MIT) |
| **GitHub Action** | ✅ published in-repo | `uses: cisoventures/vulngate@v1`. Marketplace listing is a one-time click in the repo UI (Releases → publish this Action to Marketplace). |
| **PyPI** | ⬜ pending | `vulngate` (name confirmed free). Publish with `python -m build && twine upload dist/*`. Makes `pip install "vulngate[scanners]"` real. |
| **MCP registries** | ⬜ pending | Submit the local stdio server (`vulngate-mcp`) to the modelcontextprotocol registry + awesome-mcp-servers once PyPI is live (install command needs to resolve). |
| **awesome-lists** | ⬜ pending | PRs to awesome-security, awesome-devsecops, awesome-static-analysis, awesome-actions, awesome-mcp-servers. |
| **Show HN / r/programming** | ⬜ pending | One-liner: "vulngate — free, agent-neutral security gate for AI-written code. SAST + secrets + deps, one findings schema, BYO-inference. We scan the code, not the agents." |

## Positioning (keep consistent everywhere)

- Complementary to vendor-native security tooling (including Anthropic's
  Claude-native suite) — the **universal on-ramp**, not a competitor.
- We secure the **code the agents produce**, not the agents themselves (that's a
  separate space: skill/MCP supply-chain scanners).
- $0 forever, BYO-inference, community-maintained, no SLA.
