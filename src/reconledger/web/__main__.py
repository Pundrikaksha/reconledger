"""python -m reconledger.web [--host H] [--port P] [--dry-run]"""
import sys

from ..cli import main

raise SystemExit(main(["web", *sys.argv[1:]]))
