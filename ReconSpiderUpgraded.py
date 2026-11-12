#!/usr/bin/env python3
"""ReconSpiderUpgraded entry point. See README.md for usage.

    python ReconSpiderUpgraded.py https://example.com
    python ReconSpiderUpgraded.py -l targets.txt -p 4
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from reconspider.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
