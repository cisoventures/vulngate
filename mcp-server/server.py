#!/usr/bin/env python3
"""Clone-and-run entry point for the vulngate MCP server.

Prefer the installed console command once you've `pip install "vulngate[mcp]"`:

    vulngate-mcp

This shim just lets you run the server straight from a checkout:

    python mcp-server/server.py
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from vulngate.mcp_server import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
