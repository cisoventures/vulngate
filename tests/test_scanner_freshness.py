"""scripts/check_scanner_freshness.py — no network (WHI-145).

The job exists to stop scanners going silently stale, so its one unforgivable
outcome is reporting "all current" when it didn't actually check. Every failure
test below is paired with a positive control that differs only in the fault, so
a test can't pass just because the script always returns 2.
"""

import email.message
import io
import sys
import urllib.error
import urllib.request
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))

import check_scanner_freshness as csf  # noqa: E402

# Literal pins, independent of the real action.yml.
ACTION_FIXTURE = """\
      run: pip install "semgrep==1.0.0" "pip-audit==2.0.0" "anthropic==1.0.0"
    env:
      GITLEAKS_VERSION: "8.0.0"
      arch="x64"; sum="{x}"
      arch="arm64"; sum="{a}"
""".format(x="a" * 64, a="b" * 64)
CURRENT = {"semgrep": "1.0.0", "pip-audit": "2.0.0", "anthropic": "1.0.0"}
GH_LATEST = "https://api.github.com/repos/gitleaks/gitleaks/releases/latest"


def _rate_limited(url):
    hdrs = email.message.Message()
    hdrs["X-RateLimit-Remaining"] = "0"
    hdrs["X-RateLimit-Reset"] = "1790000000"
    return urllib.error.HTTPError(url, 403, "rate limit exceeded", hdrs, None)


@pytest.fixture
def fake_net(monkeypatch, tmp_path):
    """Network double: PyPI + GitHub say everything is at the pinned version."""
    action = tmp_path / "action.yml"
    action.write_text(ACTION_FIXTURE)
    monkeypatch.setattr(csf, "ACTION", action)
    monkeypatch.setattr(sys, "argv", ["check_scanner_freshness.py"])
    state = {"github_rate_limited": False, "seen": []}

    def urlopen(req, timeout=None):
        url = req.full_url
        state["seen"].append(req)
        if url.startswith("https://pypi.org/pypi/"):
            pkg = url.split("/")[4]
            return io.BytesIO(('{"info": {"version": "%s"}}' % CURRENT[pkg]).encode())
        if url == GH_LATEST:
            if state["github_rate_limited"]:
                raise _rate_limited(url)
            return io.BytesIO(b'{"tag_name": "v8.0.0"}')
        raise AssertionError(f"unexpected URL {url}")

    monkeypatch.setattr(urllib.request, "urlopen", urlopen)
    return state


# ── exit codes: 0 current · 2 the check itself failed ────────────────────────

def test_positive_control_all_current_exits_0(fake_net):
    assert csf.cli() == 0


def test_rate_limit_is_a_failure_not_all_current(fake_net, capsys):
    fake_net["github_rate_limited"] = True
    assert csf.cli() == 2
    err = capsys.readouterr().err
    assert "rate limit" in err and "NOT 'all current'" in err


def test_missing_pin_is_a_failure_not_all_current(fake_net):
    csf.ACTION.write_text(ACTION_FIXTURE.replace('"anthropic==1.0.0"', '"anthropic"'))
    assert csf.cli() == 2


def test_missing_gitleaks_pin_is_a_failure(fake_net):
    csf.ACTION.write_text(ACTION_FIXTURE.replace("GITLEAKS_VERSION", "GL_VER"))
    assert csf.cli() == 2


# ── the token: sent to the GitHub API only, never across a redirect ──────────

def test_token_sent_to_github_api(fake_net, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok123")
    csf.cli()
    gh = [r for r in fake_net["seen"] if r.full_url == GH_LATEST]
    assert gh and gh[0].get_header("Authorization") == "Bearer tok123"


def test_token_never_sent_to_other_hosts(fake_net, monkeypatch):
    monkeypatch.setenv("GITHUB_TOKEN", "tok123")
    csf.cli()
    others = [r for r in fake_net["seen"] if r.full_url != GH_LATEST]
    assert others, "positive control: PyPI was queried"
    assert all(r.get_header("Authorization") is None for r in others)
    dl = csf._request("https://github.com/gitleaks/gitleaks/releases/download/v8.0.0/x.txt")
    assert dl.get_header("Authorization") is None


def test_no_token_no_header(monkeypatch):
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    assert csf._request(GH_LATEST).get_header("Authorization") is None


def test_token_does_not_survive_a_redirect(monkeypatch):
    """Uses the stdlib's own redirect logic, so this checks what 'unredirected' really does."""
    monkeypatch.setenv("GITHUB_TOKEN", "tok123")
    req = csf._request(GH_LATEST)
    assert req.get_header("Authorization") == "Bearer tok123"   # detector sees it before...
    hop = urllib.request.HTTPRedirectHandler().redirect_request(
        req, None, 302, "Found", {}, "https://evil.example/elsewhere")
    assert hop.get_header("Authorization") is None               # ...and not after
