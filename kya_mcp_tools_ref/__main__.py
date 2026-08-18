"""Allow ``python -m kya_mcp_tools_ref`` as an alternative to the CLI script."""
from __future__ import annotations

import sys

from kya_mcp_tools_ref.cli import main

if __name__ == "__main__":
    sys.exit(main())
