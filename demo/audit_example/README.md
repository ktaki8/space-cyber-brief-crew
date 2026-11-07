# Auditor example

`flawed_brief.md` is a **hand-written teaching example with planted errors**. It is not output from the pipeline. It shows what `briefaudit` catches, using the three fictional documents in `demo/injection/` as its sources:

| Planted error | What catches it |
| --- | --- |
| "about 4,000" interfaces (the source says about 40) | provenance: a number found in no source |
| Attribution to "Crimson Meridian" (named only inside an injected HTML comment) | quarantine leak and provenance: injected text never counts as evidence |
| T1999 (not a real technique) | MITRE check: does not exist |
| T0855 (revoked in ATT&CK v20) | MITRE check: revoked, replacement named |
| "No vendor advisory has been published" | absence claim the source does not state |

```bash
python -m briefaudit audit demo/audit_example/flawed_brief.md --sources demo/injection \
    --brief-format --canaries demo/injection_canaries.json --html output/audit_example.html
```
