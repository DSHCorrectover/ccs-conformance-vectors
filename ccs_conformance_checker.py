"""Entry-point shim for ccs-conformance-check.

Imports and runs the independent checker via importlib so it works both from
a source checkout and when installed as a pip package.
"""
from __future__ import annotations

import importlib.util
import os
import sys


def _load_checker():
    """Find and load independent_checker.py as a module."""
    # Try package-relative first (when installed via pip)
    try:
        from checkers import independent_checker  # type: ignore
        return independent_checker
    except ImportError:
        pass

    # Try filesystem-relative (when run from source checkout)
    here = os.path.dirname(os.path.abspath(__file__))
    candidate = os.path.join(here, "checkers", "independent_checker.py")
    if not os.path.isfile(candidate):
        candidate = os.path.join(os.getcwd(), "checkers", "independent_checker.py")
    if not os.path.isfile(candidate):
        print(
            f"error: cannot find checkers/independent_checker.py "
            f"(looked in {here} and cwd)",
            file=sys.stderr,
        )
        sys.exit(2)

    spec = importlib.util.spec_from_file_location(
        "ccs_independent_checker", candidate
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # type: ignore[union-attr]
    return mod


def main() -> None:
    mod = _load_checker()
    # If the module has a main(), call it; otherwise it may run at import time
    if hasattr(mod, "main"):
        sys.exit(mod.main())


if __name__ == "__main__":
    main()
