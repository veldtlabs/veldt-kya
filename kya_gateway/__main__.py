"""Allow `python -m kya_gateway` as an alternative to the `kya-gateway` CLI."""
from __future__ import annotations

import sys

from kya_gateway.cli import main

if __name__ == "__main__":
    sys.exit(main())
