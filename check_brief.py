"""Compatibility entry point. The checks now live in briefaudit.checks.

    python check_brief.py output/daily_brief.md --sources sources
"""
import sys

from briefaudit import checks as _checks

if __name__ == "__main__":
    sys.exit(_checks.main())

sys.modules[__name__] = _checks
