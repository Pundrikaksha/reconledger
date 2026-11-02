#!/usr/bin/env python3
"""Same as `reconledger demo-containment [--dry-run]`."""
import sys

from reconledger.cli import main

raise SystemExit(main(["demo-containment", *sys.argv[1:]]))
