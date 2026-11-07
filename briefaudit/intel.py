"""Public reference data for verifying identifiers in a brief.

The bundled index (briefaudit/data/intel_index.json) lets the auditor run
fully offline, which matters for air-gapped analysis and conference Wi-Fi.
Refresh it with:

    python -m briefaudit update-intel

Sources, all published by their owners on GitHub:
  - MITRE ATT&CK Enterprise, ICS and Mobile (STIX 2.1)
  - MITRE ATLAS (adversarial machine learning techniques)
  - CISA Known Exploited Vulnerabilities catalog

NVD lookups are optional and online only (`lookup_nvd`). Results are cached
on disk, and an NVD_API_KEY environment variable raises the rate limit.
"""
import json
import os
import re
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

DATA_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data")
INDEX_PATH = os.path.join(DATA_DIR, "intel_index.json")
CACHE_DIR = os.path.join(os.path.expanduser("~"), ".cache", "briefaudit")

ATTACK_BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/"
ATTACK_DOMAINS = {
    "enterprise": ATTACK_BASE + "enterprise-attack/enterprise-attack.json",
    "ics": ATTACK_BASE + "ics-attack/ics-attack.json",
    "mobile": ATTACK_BASE + "mobile-attack/mobile-attack.json",
}
ATLAS_URL = "https://raw.githubusercontent.com/mitre-atlas/atlas-data/main/dist/ATLAS.yaml"
KEV_URL = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}"

TECHNIQUE_ID = re.compile(r"^(?:AML\.)?T\d{4}(?:\.\d{3})?$")


def _fetch(url, timeout=120):
    req = urllib.request.Request(url, headers={"User-Agent": "briefaudit"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _attack_techniques(stix, domain):
    out, ids = {}, {}
    objects = stix.get("objects", [])
    for obj in objects:
        if obj.get("type") == "attack-pattern":
            ext = next((r for r in obj.get("external_references", []) if r.get("external_id")), None)
            if ext:
                ids[obj["id"]] = ext["external_id"]
    revoked_by = {rel["source_ref"]: rel["target_ref"] for rel in objects
                  if rel.get("type") == "relationship" and rel.get("relationship_type") == "revoked-by"}
    for obj in objects:
        if obj.get("type") != "attack-pattern":
            continue
        ext = next((r for r in obj.get("external_references", [])
                    if r.get("source_name") in ("mitre-attack", "mitre-ics-attack", "mitre-mobile-attack")
                    and r.get("external_id")), None)
        if not ext:
            continue
        tid = ext["external_id"]
        entry = {"name": obj.get("name", ""), "domain": domain}
        if obj.get("revoked"):
            entry["revoked"] = True
            target = ids.get(revoked_by.get(obj["id"], ""))
            if target:
                entry["replaced_by"] = target
        if obj.get("x_mitre_deprecated"):
            entry["deprecated"] = True
        # Keep the active entry if the same ID appears twice.
        if tid not in out or not (entry.get("revoked") or entry.get("deprecated")):
            out[tid] = entry
    return out


def _atlas_techniques(doc):
    out = {}
    for matrix in doc.get("matrices", []):
        for t in matrix.get("techniques", []):
            if t.get("id", "").startswith("AML.T"):
                out[t["id"]] = {"name": t.get("name", ""), "domain": "atlas"}
    return out


def build_index(attack_files=None, atlas_file=None, kev_file=None):
    """Build the compact index. Arguments are local paths (for offline builds
    and tests); anything not given is downloaded."""
    import yaml

    techniques, versions = {}, {}
    for domain, url in ATTACK_DOMAINS.items():
        path = (attack_files or {}).get(domain)
        raw = open(path, "rb").read() if path else _fetch(url, timeout=300)
        stix = json.loads(raw)
        techniques.update(_attack_techniques(stix, domain))
        coll = next((o for o in stix.get("objects", []) if o.get("type") == "x-mitre-collection"), {})
        versions["attack_" + domain] = coll.get("x_mitre_version", "")

    raw = open(atlas_file, "rb").read() if atlas_file else _fetch(ATLAS_URL)
    atlas = yaml.safe_load(raw)
    techniques.update(_atlas_techniques(atlas))
    versions["atlas"] = str(atlas.get("version", ""))

    raw = open(kev_file, "rb").read() if kev_file else _fetch(KEV_URL)
    kev_doc = json.loads(raw)
    kev = {v["cveID"].upper(): {"vendor": v.get("vendorProject", ""), "product": v.get("product", ""),
                                "added": v.get("dateAdded", ""),
                                "ransomware": v.get("knownRansomwareCampaignUse", "") == "Known"}
           for v in kev_doc.get("vulnerabilities", [])}
    versions["kev"] = kev_doc.get("catalogVersion", "")

    return {"built": datetime.now(timezone.utc).strftime("%Y-%m-%d"), "versions": versions,
            "techniques": techniques, "kev": kev}


def save_index(index, path=INDEX_PATH):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(index, f, separators=(",", ":"), sort_keys=True)


_INDEX = None


def load_index(path=INDEX_PATH):
    global _INDEX
    if path == INDEX_PATH and _INDEX is not None:
        return _INDEX
    if not os.path.isfile(path):
        return {"built": None, "versions": {}, "techniques": {}, "kev": {}}
    with open(path, "r", encoding="utf-8") as f:
        index = json.load(f)
    if path == INDEX_PATH:
        _INDEX = index
    return index


def technique_status(tid, index):
    """('valid' | 'deprecated' | 'revoked' | 'unknown', entry or None).

    A sub-technique (T1566.001) whose parent exists but is not itself listed
    is reported as unknown: inventing a plausible sub-technique number is a
    common model error."""
    entry = index["techniques"].get(tid)
    if not entry:
        return "unknown", None
    if entry.get("revoked"):
        return "revoked", entry
    if entry.get("deprecated"):
        return "deprecated", entry
    return "valid", entry


# ---------------------------------------------------------------- NVD (online)

def _cache_path():
    return os.path.join(CACHE_DIR, "nvd_cache.json")


def _load_cache():
    try:
        with open(_cache_path(), "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return {}


def _save_cache(cache):
    try:
        os.makedirs(CACHE_DIR, exist_ok=True)
        with open(_cache_path(), "w", encoding="utf-8") as f:
            json.dump(cache, f)
    except OSError:
        pass


def _parse_nvd(payload):
    vulns = payload.get("vulnerabilities") or []
    if not vulns:
        return {"exists": False}
    cve = vulns[0]["cve"]
    score, severity = None, None
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            score, severity = data.get("baseScore"), data.get("baseSeverity")
            break
    desc = next((d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"), "")
    return {"exists": True, "status": cve.get("vulnStatus", ""), "score": score,
            "severity": (severity or "").lower() or None, "description": desc[:300]}


def lookup_nvd(cve_ids, timeout=15, api_key=None):
    """{CVE: {'exists': bool, 'score', 'severity', ...} or {'error': str}}.

    Cached for 7 days. Without an API key NVD allows about 5 requests per
    30 seconds, so requests are spaced out."""
    api_key = api_key or os.getenv("NVD_API_KEY")
    cache, now, out = _load_cache(), time.time(), {}
    delay = 0.7 if api_key else 6.5
    fetched = 0
    for cve in sorted({c.upper() for c in cve_ids}):
        hit = cache.get(cve)
        if hit and now - hit.get("_t", 0) < 7 * 86400:
            out[cve] = {k: v for k, v in hit.items() if k != "_t"}
            continue
        if fetched:
            time.sleep(delay)
        headers = {"User-Agent": "briefaudit"}
        if api_key:
            headers["apiKey"] = api_key
        try:
            req = urllib.request.Request(NVD_URL.format(cve), headers=headers)
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                result = _parse_nvd(json.loads(resp.read()))
            fetched += 1
            cache[cve] = dict(result, _t=now)
            out[cve] = result
        except (urllib.error.URLError, OSError, ValueError, KeyError) as e:
            out[cve] = {"error": str(e)[:120]}
    _save_cache(cache)
    return out
