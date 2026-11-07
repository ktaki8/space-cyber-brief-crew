"""Dashboard endpoints: auditing is free and path-restricted; live runs need a key."""
from fastapi.testclient import TestClient

import api

client = TestClient(api.app)


def test_dashboard_page_served():
    r = client.get("/dashboard")
    assert r.status_code == 200 and "Brief Audit Console" in r.text


def test_options_list_sources_briefs_and_reference_data():
    o = client.get("/api/audit/options").json()
    assert any(s["id"] == "demo/injection" and s["available"] for s in o["source_sets"])
    assert "demo/audit_example/flawed_brief.md" in o["briefs"]
    assert o["reference_data"]["attack_enterprise"]


def test_audit_flawed_example():
    r = client.post("/api/audit", json={"sources": "demo/injection",
                                        "brief_path": "demo/audit_example/flawed_brief.md"})
    d = r.json()
    assert r.status_code == 200 and d["failed"]
    assert any(c["label"] == "unsupported" and "4,000" in c["missing"] for c in d["claims"])
    assert 'class="c c-unsupported"' in d["brief_html"]
    assert any('class="q"' in s["html"] for s in d["sources"])


def test_audit_pasted_brief_generic():
    text = ("## Finding\n\n### What Happened\nThe Hexlink GS-400 ground station modem ships with a default "
            "administrator password (CVE-2026-40117).\n\nSource: ground_station_modem_advisory.md\n")
    d = client.post("/api/audit", json={"sources": "demo/injection", "brief_text": text,
                                        "brief_format": False}).json()
    assert d["claims_summary"]["supported"] == 1


def test_audit_rejects_unknown_sources_and_paths():
    assert client.post("/api/audit", json={"sources": "/etc", "brief_path": "output/daily_brief.md"}).status_code == 400
    assert client.post("/api/audit", json={"sources": "sources", "brief_path": "../../etc/passwd"}).status_code == 400


def test_live_demo_requires_key(monkeypatch):
    monkeypatch.delenv("CREW_ACCESS_KEY", raising=False)
    assert client.post("/api/demo/injection", json={"defenses": False}).status_code == 503
    monkeypatch.setenv("CREW_ACCESS_KEY", "right")
    r = client.post("/api/demo/injection", json={"defenses": False}, headers={"X-Access-Key": "wrong"})
    assert r.status_code == 401
