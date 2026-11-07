"""briefaudit command line.

    briefaudit audit REPORT.md --sources DIR [--html out.html] [--sarif out.sarif] [--json] [--online]
    briefaudit update-intel

`audit` works on a threat report from any tool or model. By default it skips
this project's own format rules (classification marking, date line); add
--brief-format to apply them to Space-Cyber Brief Crew output.

Exit codes: 0 no FAIL, 1 at least one FAIL, 2 bad input.
"""
import argparse
import json
import os
import sys

from . import __version__, intel
from .checks import check, load_canaries
from .corpus import load_corpus
from .report import to_sarif, write_html


def _audit(args):
    if not os.path.isfile(args.report):
        print(f"Report not found: {args.report}", file=sys.stderr)
        return 2
    corpus = load_corpus(args.sources)
    if not corpus:
        print(f"No .txt or .md sources found in {args.sources}", file=sys.stderr)
        return 2
    with open(args.report, "r", encoding="utf-8") as f:
        text = f.read()
    must, review = load_canaries(args.canaries)
    catalog = None
    if args.tle:
        from orbital import Catalog
        catalog = Catalog.from_file(args.tle)
    result = check(text, corpus, must, review, profile="brief" if args.brief_format else "generic",
                   online=args.online, tle_catalog=catalog)

    if args.html:
        write_html(args.html, os.path.basename(args.report), text, corpus, result)
    if args.sarif:
        with open(args.sarif, "w", encoding="utf-8") as f:
            json.dump(to_sarif(args.report, result, __version__), f, indent=2)

    if args.json:
        print(json.dumps({"report": args.report, "failed": result.failed, "results": result.results,
                          "claims_summary": result.claim_summary,
                          "claims": [c.as_dict() for c in result.claims]}, indent=2))
    else:
        idx = intel.load_index()
        print(f"briefaudit {__version__}: {args.report} against {args.sources}/ ({len(corpus)} source(s))")
        if idx.get("built"):
            v = idx["versions"]
            print(f"Reference data: ATT&CK v{v.get('attack_enterprise')}, ATLAS {v.get('atlas')}, "
                  f"KEV {v.get('kev')}" + (", NVD live" if args.online else ""))
        print()
        for r in result.results:
            print(f"  {r['level']:<4}  {r['check']:<14} {r['message']}")
        s = result.claim_summary
        if s.get("claims"):
            print(f"\n  Claims: {s['supported']} supported, {s['partial']} partial, {s['unsupported']} "
                  f"unsupported, {s['absence_claims']} absence, {s['judgment']} judgment")
        if args.html:
            print(f"\n  HTML report: {args.html}")
        print("\nResult:", "FAIL" if result.failed else "PASS (automated checks only; an analyst still signs off)")
    return 1 if result.failed else 0


def _update(args):
    print("Downloading MITRE ATT&CK, MITRE ATLAS and CISA KEV ...")
    index = intel.build_index()
    intel.save_index(index, args.out)
    v = index["versions"]
    print(f"Saved {args.out}: {len(index['techniques'])} techniques "
          f"(ATT&CK v{v.get('attack_enterprise')}, ATLAS {v.get('atlas')}), "
          f"{len(index['kev'])} KEV entries (catalog {v.get('kev')})")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog="briefaudit", description="Verify AI-written threat intelligence.")
    p.add_argument("--version", action="version", version=f"briefaudit {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("audit", help="audit a report against its source documents")
    a.add_argument("report")
    a.add_argument("--sources", required=True, help="folder of .txt/.md documents the report is based on")
    a.add_argument("--html", help="write an interactive HTML report")
    a.add_argument("--sarif", help="write SARIF 2.1.0 (GitHub code scanning, SIEM import)")
    a.add_argument("--json", action="store_true", help="print JSON instead of text")
    a.add_argument("--online", action="store_true", help="verify CVEs against NVD")
    a.add_argument("--canaries", help="JSON with must_not_appear / review_terms (injection tests)")
    a.add_argument("--tle", default=os.getenv("ORBITAL_TLE"),
                   help="element sets (3LE) for testing orbital claims; default $ORBITAL_TLE")
    a.add_argument("--brief-format", action="store_true",
                   help="also apply Space-Cyber Brief Crew format rules (marking, date line)")
    a.set_defaults(func=_audit)

    u = sub.add_parser("update-intel", help="refresh the bundled MITRE and KEV reference data")
    u.add_argument("--out", default=intel.INDEX_PATH)
    u.set_defaults(func=_update)

    args = p.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
