"""Plain-English knowledge pack — the vibe-coder layer.

Scanners emit jargon ("python.lang.security.audit.dangerous-subprocess-use",
"CWE-78"). A user who can't read that still deserves to understand the risk.
This module maps findings to one jargon-free sentence: what it means for YOU.

It is 100% deterministic and offline — no LLM, no cost. When a rule isn't
covered yet we fall back to the scanner's own description. New entries are
easy, self-contained contributions (good first issues).
"""

from __future__ import annotations

# Keyed by CWE — the most portable identity across scanners.
CWE_SUMMARIES: dict[str, str] = {
    "CWE-78":  "Your code builds a system command out of input it doesn't control. An attacker could sneak in extra commands and run anything on your server.",
    "CWE-79":  "Your code puts untrusted input straight into a web page. An attacker could inject a script that runs in your users' browsers (XSS).",
    "CWE-89":  "Your code builds a database query out of untrusted input. An attacker could rewrite the query to read or delete data (SQL injection).",
    "CWE-22":  "Your code builds a file path out of untrusted input. An attacker could escape the intended folder and reach other files (path traversal).",
    "CWE-94":  "Your code runs text as code (e.g. eval). If any of that text comes from a user, they can run their own code.",
    "CWE-95":  "Your code evaluates a string as code. Untrusted input here lets an attacker run whatever they want.",
    "CWE-502": "Your code unpacks saved data from an untrusted source. Crafted data can trick it into running malicious code (insecure deserialization).",
    "CWE-611": "Your XML parser will follow external references. An attacker can use that to read local files or hit internal systems (XXE).",
    "CWE-327": "Your code uses a broken or outdated encryption method. It can be cracked, so anything it protects isn't really safe.",
    "CWE-326": "Your code uses weak encryption strength. It may not actually protect the data it's meant to.",
    "CWE-328": "Your code uses a weak hash (like MD5 or SHA-1). These are broken for security use — switch to SHA-256 or better.",
    "CWE-330": "Your code uses a predictable random generator for something security-sensitive. Attackers can guess the values.",
    "CWE-798": "A secret (password, API key, or token) is written directly into your code. Anyone who can read the code can use it.",
    "CWE-259": "A password is written directly into your code. Move it out and change it — assume it's already exposed.",
    "CWE-319": "Your code sends sensitive data without encryption. Anyone on the network can read it — use HTTPS/TLS.",
    "CWE-311": "Sensitive data is being stored or sent without encryption. It should be protected in transit and at rest.",
    "CWE-352": "A form or action can be triggered by another site on a logged-in user's behalf (CSRF). Add anti-CSRF protection.",
    "CWE-1004": "A login/session cookie is missing the httpOnly flag, so page scripts can read it. If your site has any XSS, attackers can steal the session.",
    "CWE-295": "Your code skips or ignores TLS certificate checks. That defeats HTTPS — attackers can impersonate the server.",
}

# Keyed by substrings that show up in rule IDs, when no CWE is present.
KEYWORD_SUMMARIES: list[tuple[str, str]] = [
    ("subprocess",  CWE_SUMMARIES["CWE-78"]),
    ("command-injection", CWE_SUMMARIES["CWE-78"]),
    ("shell", CWE_SUMMARIES["CWE-78"]),
    ("sql", CWE_SUMMARIES["CWE-89"]),
    ("xss", CWE_SUMMARIES["CWE-79"]),
    ("eval", CWE_SUMMARIES["CWE-94"]),
    ("pickle", CWE_SUMMARIES["CWE-502"]),
    ("yaml.load", CWE_SUMMARIES["CWE-502"]),
    ("deserial", CWE_SUMMARIES["CWE-502"]),
    ("md5", CWE_SUMMARIES["CWE-328"]),
    ("sha1", CWE_SUMMARIES["CWE-328"]),
    ("weak-crypto", CWE_SUMMARIES["CWE-327"]),
    ("verify=false", CWE_SUMMARIES["CWE-295"]),
    ("ssl", CWE_SUMMARIES["CWE-295"]),
    ("hardcoded", CWE_SUMMARIES["CWE-798"]),
    ("secret", CWE_SUMMARIES["CWE-798"]),
    ("httponly", CWE_SUMMARIES["CWE-1004"]),
    ("random", CWE_SUMMARIES["CWE-330"]),
    ("path-traversal", CWE_SUMMARIES["CWE-22"]),
]

# Last-resort default per scanner, keyed by our normalized scanner name.
SCANNER_DEFAULTS: dict[str, str] = {
    "gitleaks":  "A secret (password, API key, or token) appears to be hard-coded in your code. Anyone who can see this code can use it — move it to an environment variable and rotate the exposed value.",
    "pip-audit": "A Python package you depend on has a publicly known security flaw. Upgrading it to a fixed version closes the hole.",
    "npm-audit": "An npm package you depend on has a publicly known security flaw. Upgrading it to a fixed version closes the hole.",
    "semgrep":   "A risky code pattern was found that an attacker could potentially misuse. Review the suggested fix.",
}


def plain_summary(
    *, scanner: str, rule: str, cwes: list[str], description: str
) -> str:
    """Best available jargon-free explanation for a finding."""
    for cwe in cwes:
        if cwe in CWE_SUMMARIES:
            return CWE_SUMMARIES[cwe]
    rule_l = (rule or "").lower()
    for keyword, text in KEYWORD_SUMMARIES:
        if keyword in rule_l:
            return text
    if scanner in SCANNER_DEFAULTS:
        return SCANNER_DEFAULTS[scanner]
    return description or "A potential security issue was found. Review it before shipping."
