"""Entry-point shim for ccs-conformance-check.

Runs the independent checker at checkers/independent_checker.py via runpy so
the checker itself remains a single zero-dependency file with no package
structure required.
"""
from __future__ import annotations

import os
import runpy
import sys


def _find_checker() -> str:
    """Locate independent_checker.py relative to this module or sys.prefix."""
    here = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(here, "checkers", "independent_checker.py"),
        os.path.join(sys.prefix, "checkers", "independent_checker.py"),
        os.path.join(os.path.dirname(sys.executable), "checkers", "independent_checker.py"),
    ]
    for c in candidates:
        if os.path.isfile(c):
            return c
    searched = "\n  ".join(candidates)
    print(f"error: cannot find independent_checker.py, searched:\n  {searched}", file=sys.stderr)
    sys.exit(2)


def main() -> None:
    checker = _find_checker()
    sys.argv[0] = checker
    runpy.run_path(checker, run_name="__main__")


if __name__ == "__main__":
    main()
