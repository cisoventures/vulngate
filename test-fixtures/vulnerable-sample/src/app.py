"""Deliberately vulnerable sample — DO NOT copy these patterns into real code.
Used to verify vulngate end-to-end. Every function here is an intentional bug.
"""

import hashlib
import subprocess


def list_dir(user_input):
    # CWE-78: builds a shell command from untrusted input (command injection)
    return subprocess.call("ls " + user_input, shell=True)


def evaluate(expr):
    # CWE-94: runs a string as code (code injection)
    return eval(expr)


def hash_password(password):
    # CWE-328: weak hash for a password
    return hashlib.md5(password.encode()).hexdigest()


# CWE-798: hard-coded credential in source. Deliberately NOT a real provider key
# format — a validated-format secret here would trip secret-scanning push
# protection on this repo and in every fork. The seeded secret gitleaks/semgrep
# catch in the end-to-end demo lives in config.py.
HARDCODED_TOKEN = "vulngate-EXAMPLE-placeholder-not-a-real-key"
