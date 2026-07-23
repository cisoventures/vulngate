"""Auto-detect what's in the target repo so we only run relevant scanners.

Zero config to start: the presence of lockfiles/manifests and source files
decides which scanners apply. No manual language flags required.
"""

from __future__ import annotations

import fnmatch
import os
from dataclasses import dataclass, field
from pathlib import Path

# Directories never worth scanning — pruned during the walk.
IGNORE_DIRS = {
    ".git", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "dist", "build",
    ".next", ".nuxt", ".tox", ".idea", ".vscode", "vendor", ".gradle",
    "target", ".terraform", "coverage", ".cache",
}

EXT_LANG = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "typescript", ".tsx": "typescript", ".go": "go",
    ".rb": "ruby", ".java": "java", ".php": "php", ".cs": "csharp",
    ".rs": "rust", ".c": "c", ".cpp": "cpp", ".sh": "shell",
}

PY_MANIFEST_GLOBS = ("requirements*.txt",)


@dataclass
class Detection:
    root: Path
    languages: set[str] = field(default_factory=set)
    py_requirements: list[Path] = field(default_factory=list)   # requirements*.txt files
    npm_lock_dirs: list[Path] = field(default_factory=list)     # dirs containing package-lock.json
    file_count: int = 0


def _excluded(rel: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(rel, pat) for pat in patterns)


def detect(root: Path, exclude: list[str] | None = None) -> Detection:
    exclude = exclude or []
    det = Detection(root=root)
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune ignored + excluded directories in place.
        dirnames[:] = [
            d for d in dirnames
            if d not in IGNORE_DIRS
            and not _excluded(str(Path(dirpath, d).relative_to(root)), exclude)
        ]
        here = Path(dirpath)
        for fn in filenames:
            rel = str((here / fn).relative_to(root))
            if _excluded(rel, exclude):
                continue
            det.file_count += 1
            ext = os.path.splitext(fn)[1].lower()
            if ext in EXT_LANG:
                det.languages.add(EXT_LANG[ext])
            if fn == "package-lock.json":
                det.npm_lock_dirs.append(here)
            if any(fnmatch.fnmatch(fn, g) for g in PY_MANIFEST_GLOBS):
                det.py_requirements.append(here / fn)
    return det
