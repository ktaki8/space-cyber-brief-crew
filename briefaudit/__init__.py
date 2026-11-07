"""briefaudit: verify AI-written threat intelligence before anyone trusts it.

Checks a brief or report against the documents it claims to be based on,
and against public reference data (MITRE ATT&CK, MITRE ATLAS, CISA KEV, and
optionally NVD). Works on output from any model or pipeline, not only
Space-Cyber Brief Crew.
"""
__version__ = "0.3.0"
