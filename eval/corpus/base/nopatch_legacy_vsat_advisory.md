# Advisory: Hard-Coded Credentials in Meridan VT-20 VSAT Terminals

- **Source:** Illustrative sample written for this evaluation. Not real reporting. Products, organizations, and identifiers are fictional. Vendor advisory.
- **Date:** October 20, 2026

Meridan VT-20 VSAT terminals contain a hard-coded maintenance account
(CVE-2026-42011, fictional). The CVSS v3.1 base score is 8.1. Terminals built
after 2024 can receive a fix in firmware 3.0. Terminals built before 2024 are
end of life and will not receive a fix. Operators of those units must replace
them or isolate them from untrusted networks.

Recommended actions:
- Apply firmware 3.0 to supported terminals.
- Replace or isolate terminals built before 2024.
