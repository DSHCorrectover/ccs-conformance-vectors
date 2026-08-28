"""Entry-point shim for ccs-conformance-check.

Runs the independent checker at checkers/independent_checker.py via runpy so
the checker itself remains a single zero-dependency file with no package
structure required.
"""
from __future__ import annotations

import os
import runpy
import sys


def main() -> None:
    here = os.path.dirname(os.path.abspath(__file__))
    checker = os.path.join(here, "checkers", "independent_checker.py")
    if not os.path.exists(checker):
        # When installed as a console script, checkers/ may live beside the
        # installed module file.
        checker = os.path.join(os.path.dirname(sys.executable), "checkers", "independent_checker.py")
    if not os.path.exists(checker):
        print(f"error: cannot find independent_checker.py (looked in {here})", file=sys.stderr)
        sys.exit(2)
    sys.argv[0] = checker
    runpy.run_path(checker, run_name="__main__")


if __name__ == "__main__":
    main()
