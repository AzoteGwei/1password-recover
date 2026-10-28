#!/usr/bin/env python3
"""
Backward-compatibility entrypoint for get_items.py.
Redirects to the modernized Python 3 + UV recovery engine.
"""
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from recover_op.cli import main

if __name__ == "__main__":
    main()

