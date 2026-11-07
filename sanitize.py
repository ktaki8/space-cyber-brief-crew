"""Compatibility shim: the sanitizer now lives in briefaudit.sanitizer."""
from briefaudit.sanitizer import *  # noqa: F401,F403
from briefaudit.sanitizer import MARKER, Finding, SanitizeResult, sanitize_text  # noqa: F401
