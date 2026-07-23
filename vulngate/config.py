"""Optional zero-required config. Same file is reused by every later phase so
behavior is identical in the CLI, the Action, and the MCP server.

Looked up (first match wins): --config PATH, then vulngate.toml, then
.vulngate.toml at the target root. Accepts either top-level keys or a
[vulngate] / [tool.vulngate] table.

    fail_on = "high"            # critical | high | medium | low
    exclude = ["tests/*", "*.min.js"]
    disable = ["gitleaks"]      # scanner names to skip
    ignore  = ["vg_ab12...", "python.lang.security.audit.some-rule"]  # finding id or rule
    no_deps = false             # pass --no-deps to pip-audit (for fully-pinned req files)
    dependency_severity = "medium"  # severity for dep findings that lack a CVSS score
"""

from __future__ import annotations

import tomllib
from pathlib import Path

DEFAULTS = {
    "fail_on": "high",
    "exclude": [],
    "disable": [],
    "ignore": [],
    "no_deps": False,
    "dependency_severity": "medium",
}
_CANDIDATES = ("vulngate.toml", ".vulngate.toml")


class ConfigError(ValueError):
    pass


def load_config(root: Path, explicit_path: str | None) -> dict:
    path: Path | None = None
    if explicit_path:
        path = Path(explicit_path)
        if not path.exists():
            raise ConfigError(f"config file not found: {explicit_path}")
    else:
        for name in _CANDIDATES:
            if (root / name).exists():
                path = root / name
                break

    cfg = dict(DEFAULTS)
    if path is None:
        return cfg
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (tomllib.TOMLDecodeError, OSError) as e:
        raise ConfigError(f"could not read config {path}: {e}") from e

    table = raw.get("vulngate") or raw.get("tool", {}).get("vulngate") or raw
    for key in DEFAULTS:
        if key in table:
            cfg[key] = table[key]
    if cfg["fail_on"] not in ("critical", "high", "medium", "low"):
        raise ConfigError(f"invalid fail_on: {cfg['fail_on']!r}")
    if cfg["dependency_severity"] not in ("critical", "high", "medium", "low"):
        raise ConfigError(f"invalid dependency_severity: {cfg['dependency_severity']!r}")
    return cfg
