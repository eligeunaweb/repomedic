import argparse
import json
from pathlib import Path
from .audit import scan, html_report

def main(argv=None):
    parser = argparse.ArgumentParser(description="Offline-first repository health checks")
    parser.add_argument("path", nargs="?", default=".", help="Repository directory")
    parser.add_argument("--format", choices=["text", "json", "html"], default="text")
    parser.add_argument("--output", help="Write report to a file")
    parser.add_argument("--fail-on-high", action="store_true", help="Exit with status 1 when high severity findings exist")
    parser.add_argument("--profile", choices=["auto", "generic", "odoo"], default="auto", help="Audit profile; auto detects Odoo module roots")
    args = parser.parse_args(argv)
    try: report = scan(Path(args.path), profile=args.profile)
    except (OSError, ValueError) as exc:
        parser.exit(2, f"repomedic: {exc}\n")
    if args.format == "json": rendered = json.dumps(report, indent=2, ensure_ascii=False)
    elif args.format == "html": rendered = html_report(report)
    else:
        lines = [f"RepoMedic: {report['files_scanned']} files scanned"]
        lines += [f"[{f['severity']}] {f['id']} {f.get('path','')}:{f.get('line','')} — {f['message']}" for f in report['findings']]
        rendered = "\n".join(lines)
    if args.output: Path(args.output).write_text(rendered + "\n", encoding="utf-8")
    else: print(rendered)
    return 1 if args.fail_on_high and report["summary"]["high"] else 0

if __name__ == "__main__": raise SystemExit(main())
