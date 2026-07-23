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
    # ── input handling & injection ───────────────────────────────────────────
    "CWE-20":  "Your code trusts input without checking it. Malformed or malicious values can slip through and break assumptions elsewhere — validate what comes in.",
    "CWE-77":  "Your code builds a system command out of input it doesn't fully control. An attacker could inject extra commands (command injection).",
    "CWE-90":  "Your code builds an LDAP query out of untrusted input. An attacker could rewrite it to bypass logins or read directory data (LDAP injection).",
    "CWE-113": "Your code puts untrusted input into an HTTP header. An attacker could inject extra headers or split the response (header injection).",
    "CWE-116": "Output isn't escaped for where it's used, so special characters can change how it's interpreted downstream.",
    "CWE-117": "Untrusted input is written straight to your logs. An attacker could forge log entries or inject content that harms whoever reads them (log injection).",
    "CWE-601": "Your code redirects users to a URL built from untrusted input. An attacker could send victims to a malicious site that looks like it came from you (open redirect).",
    "CWE-776": "Your XML parser expands entities without limit. A tiny crafted file can blow up memory and crash the service (billion laughs).",
    "CWE-915": "Your code assigns request data directly onto an object's fields. An attacker could set fields you never meant to expose (mass assignment).",
    "CWE-918": "Your server makes a request to a URL built from untrusted input. An attacker could point it at internal systems or cloud metadata (SSRF).",
    "CWE-943": "Your code builds a NoSQL query out of untrusted input. An attacker could alter the query's logic (NoSQL injection).",
    "CWE-1236": "Untrusted input goes into a spreadsheet/CSV cell. Opened in Excel, a crafted value can run as a formula on the victim's machine (CSV injection).",
    "CWE-1321": "Untrusted input can modify JavaScript object prototypes, which can corrupt app logic or lead to code execution (prototype pollution).",
    # ── info exposure & error handling ───────────────────────────────────────
    "CWE-200": "Your code may expose sensitive information to someone who shouldn't see it.",
    "CWE-209": "An error message reveals internal details (stack traces, queries, paths) that help an attacker map your system. Show users a generic message.",
    "CWE-215": "Debug mode is enabled. It can leak internal details and, in some frameworks, allow remote code execution — turn it off in production.",
    "CWE-312": "Sensitive data is stored in plain text. Anyone who reads that storage gets it directly — encrypt it.",
    "CWE-522": "Credentials are stored or transmitted without enough protection, making them easy to steal.",
    # ── crypto & secrets ─────────────────────────────────────────────────────
    "CWE-321": "A cryptographic key is hard-coded in your code. Everyone with the code has the key, so it protects nothing — load it from a secret store and rotate it.",
    "CWE-338": "Your code uses a random generator that isn't cryptographically secure for something security-sensitive (tokens, keys). Attackers can predict the values — use a secure RNG.",
    "CWE-347": "Your code doesn't properly verify a cryptographic signature, so a forged or tampered message could be accepted as genuine.",
    "CWE-916": "Passwords are hashed with a fast algorithm. Fast hashes are easy to brute-force — use a slow password hash like bcrypt, scrypt, or Argon2.",
    # ── access control & auth ────────────────────────────────────────────────
    "CWE-250": "This runs with more privileges than it needs. If it's compromised, the attacker inherits that power — drop to the least privilege required.",
    "CWE-276": "A file or resource is created with overly broad permissions, letting other users on the system read or change it.",
    "CWE-284": "Access isn't properly restricted, so someone could reach an action or resource they shouldn't.",
    "CWE-287": "Authentication here is weak or can be bypassed, letting someone act without proving who they are.",
    "CWE-306": "A sensitive action is exposed without requiring login. Anyone who finds it can trigger it.",
    "CWE-307": "There's no limit on failed login attempts, so an attacker can keep guessing passwords (brute force). Add rate limiting or lockout.",
    "CWE-434": "Uploaded files aren't restricted enough. An attacker could upload an executable file and run it on your server.",
    "CWE-521": "Password rules are too weak, so users can pick easily guessed passwords.",
    "CWE-613": "Sessions don't expire soon enough, widening the window for a stolen session to be reused.",
    "CWE-614": "A session cookie is missing the Secure flag, so it can be sent over plain HTTP and intercepted.",
    "CWE-732": "A critical file or resource has permissions that are too open, letting the wrong users read or modify it.",
    "CWE-862": "This action doesn't check whether the user is allowed to do it (missing authorization). Anyone who reaches it can perform it.",
    "CWE-863": "The authorization check here is wrong, so users can act outside their permissions.",
    # ── resource handling ────────────────────────────────────────────────────
    "CWE-377": "A temporary file is created insecurely, so another user could read it or swap it out (a race condition). Use a secure temp-file API.",
    "CWE-400": "This can consume unbounded resources (memory, CPU, connections). An attacker could exhaust them and take the service down (denial of service).",
    "CWE-829": "Your code loads code or data from an untrusted source. If that source is compromised, so are you.",
}

# Keyed by substrings that show up in rule IDs, when no CWE is present.
KEYWORD_SUMMARIES: list[tuple[str, str]] = [
    ("subprocess",  CWE_SUMMARIES["CWE-78"]),
    ("command-injection", CWE_SUMMARIES["CWE-78"]),
    ("shell", CWE_SUMMARIES["CWE-78"]),
    ("nosql", CWE_SUMMARIES["CWE-943"]),   # must precede "sql" — "nosql" contains it
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
    ("directory-traversal", CWE_SUMMARIES["CWE-22"]),
    # More specific substrings than a bare CWE-less rule id would otherwise hit.
    ("ssrf", CWE_SUMMARIES["CWE-918"]),
    ("open-redirect", CWE_SUMMARIES["CWE-601"]),
    ("open_redirect", CWE_SUMMARIES["CWE-601"]),
    ("ldap", CWE_SUMMARIES["CWE-90"]),
    ("xxe", CWE_SUMMARIES["CWE-611"]),
    ("xml-external", CWE_SUMMARIES["CWE-611"]),
    ("prototype-pollution", CWE_SUMMARIES["CWE-1321"]),
    ("prototype_pollution", CWE_SUMMARIES["CWE-1321"]),
    ("mass-assignment", CWE_SUMMARIES["CWE-915"]),
    ("formula-injection", CWE_SUMMARIES["CWE-1236"]),
    ("csv-injection", CWE_SUMMARIES["CWE-1236"]),
    ("header-injection", CWE_SUMMARIES["CWE-113"]),
    ("log-injection", CWE_SUMMARIES["CWE-117"]),
    ("debug-enabled", CWE_SUMMARIES["CWE-215"]),
    ("debug-true", CWE_SUMMARIES["CWE-215"]),
    ("debug=true", CWE_SUMMARIES["CWE-215"]),
    ("insecure-random", CWE_SUMMARIES["CWE-338"]),
    ("insecure-temp", CWE_SUMMARIES["CWE-377"]),
    ("tempfile", CWE_SUMMARIES["CWE-377"]),
    ("mktemp", CWE_SUMMARIES["CWE-377"]),
    ("csrf", CWE_SUMMARIES["CWE-352"]),
    ("samesite", CWE_SUMMARIES["CWE-352"]),
    ("file-upload", CWE_SUMMARIES["CWE-434"]),
    ("weak-password", CWE_SUMMARIES["CWE-521"]),
    ("md4", CWE_SUMMARIES["CWE-328"]),
    ("rc4", CWE_SUMMARIES["CWE-327"]),
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
