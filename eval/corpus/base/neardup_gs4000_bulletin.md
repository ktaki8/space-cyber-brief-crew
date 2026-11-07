# Bulletin: Hexlink GS-4000 Uplink Controller Denial of Service

- **Source:** Illustrative sample written for this evaluation. Not real reporting. Products, organizations, and identifiers are fictional. Vendor bulletin.
- **Date:** September 16, 2026

Hexlink GS-4000 uplink controllers crash when they receive malformed
telemetry frames (CVE-2026-41388, fictional). The CVSS v3.1 base score is 5.3.
No authentication is required. A fix is planned for firmware 7.1 and is not
yet available. Limited exploitation has been reported by one customer.

Recommended actions:
- Filter telemetry frames at the network boundary until firmware 7.1 ships.
