# Distribution (Phase 4 go-to-market)

All free channels. The repo itself is the canonical landing page.

| Channel | Status | Notes |
|---|---|---|
| **GitHub repo** | ✅ live | https://github.com/cisoventures/vulngate (public, MIT) |
| **GitHub Action** | ✅ on Marketplace | https://github.com/marketplace/actions/vulngate · `uses: cisoventures/vulngate@v1`. |
| **PyPI** | ✅ live | https://pypi.org/project/vulngate/ (v1.1.0). `pip install "vulngate[scanners]"` / `[mcp]` works. Re-publish with `python -m build && twine upload dist/*`. |
| **MCP registries** | ⬜ pending | Now unblocked (PyPI live). Submit `vulngate-mcp` to the modelcontextprotocol registry + awesome-mcp-servers; install command `pip install vulngate[mcp]` / `uvx --from vulngate[mcp] vulngate-mcp` resolves. |
| **awesome-lists** | ⬜ pending | PRs to awesome-security, awesome-devsecops, awesome-static-analysis, awesome-actions, awesome-mcp-servers. |
| **Show HN / r/programming** | ⬜ pending | One-liner: "vulngate — free, agent-neutral security gate for AI-written code. SAST + secrets + deps, one findings schema, BYO-inference. We scan the code, not the agents." |

## Positioning (keep consistent everywhere)

- Complementary to vendor-native security tooling (including Anthropic's
  Claude-native suite) — the **universal on-ramp**, not a competitor.
- We secure the **code the agents produce**, not the agents themselves (that's a
  separate space: skill/MCP supply-chain scanners).
- $0 forever, BYO-inference, community-maintained, no SLA.
