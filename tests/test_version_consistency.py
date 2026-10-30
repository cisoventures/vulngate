"""The two version sources must agree.

`vulngate/__init__.py` supplies `--version` and the `tool_version` recorded in
every scan receipt; `pyproject.toml` supplies what PyPI publishes. A release
that bumps one and not the other mislabels every scan it produces.
"""
import pathlib
import sys

if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - the package requires 3.11+
    import tomli as tomllib

from vulngate import __version__


def test_package_version_matches_pyproject():
    pyproject = pathlib.Path(__file__).resolve().parent.parent / "pyproject.toml"
    declared = tomllib.loads(pyproject.read_text())["project"]["version"]
    assert declared == __version__, (
        f"pyproject.toml says {declared}, vulngate/__init__.py says {__version__}"
    )
