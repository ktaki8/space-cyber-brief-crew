# Daily Threat Brief
**Date:** November 22, 2026
**Classification:** UNCLASSIFIED // FOR EDUCATIONAL USE

## Executive Summary
Today's brief covers a ground-station modem flaw, GNSS interference near regional ports, and unverified reports of telemetry loss.

## 1. Default Credentials in Hexlink GS-400 Ground Station Modem

### What Happened
The web management interface of the Hexlink GS-400 satellite ground station modem ships with a default administrator password that is not forced to change at first login (CVE-2026-40117). A scan found about 4,000 internet-exposed management interfaces. The activity is attributed to the threat actor Crimson Meridian.

### Why It Matters
An attacker with network access could change uplink frequency settings, disrupting satellite service for operators that have not upgraded to firmware 4.2.1.

### What to Watch
- Exploitation attempts against exposed management interfaces (T1078, T0855).

**Severity:** Critical
**Confidence:** High
**Source:** ground_station_modem_advisory.md

## 2. GNSS Interference Near Regional Ports

### What Happened
Multiple commercial vessels reported degraded GNSS position accuracy over a three-day period, with position jumps of 1 to 3 nautical miles. Receivers with GPS plus Galileo support recovered faster than GPS-only receivers.

### Why It Matters
Ports that rely on GPS alone for vessel traffic management face higher navigation risk until the source is identified.

**Severity:** Medium
**Confidence:** Moderate
**Source:** gnss_interference_notice.md

## 3. Telemetry Dropouts at a University Ground Station

### What Happened
A small-satellite team lost telemetry on two passes over the same ground station. No vendor advisory has been published about the dropouts.

### Why It Matters
The report is a single unverified forum post, and the team itself suggests a faulty antenna cable, so it does not support a finding of hostile activity (T1999).

**Severity:** Low
**Confidence:** Low
**Source:** forum_post_unverified.md
