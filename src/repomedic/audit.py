"""Conservative, offline repository checks. Never reads outside the target tree."""
from __future__ import annotations
import json
import ast
import csv
import re
import tokenize
from pathlib import Path

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__", ".next"}
MAX_BYTES = 512_000
SOURCE_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".php", ".env", ".yml", ".yaml", ".json", ".ini", ".toml"}
PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"), "high", "Remove private keys from the repository and rotate compromised credentials."),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"), "high", "Revoke exposed tokens and use a secret manager."),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"), "high", "Rotate the AWS access key and move credentials out of source control."),
]

def finding(code, severity, message, path=None, line=None, advice=None):
    item = {"id": code, "severity": severity, "message": message}
    if path is not None: item["path"] = path
    if line is not None: item["line"] = line
    if advice is not None: item["advice"] = advice
    return item

def scan(root: Path, profile: str = "auto") -> dict:
    root = root.resolve(strict=True)
    if not root.is_dir(): raise ValueError("Target must be a directory")
    if profile not in ("auto", "generic", "odoo"):
        raise ValueError("Unknown profile")
    odoo = profile == "odoo" or (profile == "auto" and (root / "__manifest__.py").is_file())
    results = []
    if not odoo and not any((root / n).is_file() for n in ("README.md", "README.rst", "README.txt")):
        results.append(finding("missing-readme", "medium", "No README found", advice="Add setup and usage instructions."))
    if not odoo and not any((root / n).is_file() for n in ("LICENSE", "LICENSE.md", "LICENSE.txt", "COPYING")):
        results.append(finding("missing-license", "medium", "No license found", advice="Choose and include an appropriate open-source license."))
    if not odoo and not (root / ".gitignore").is_file():
        results.append(finding("missing-gitignore", "low", "No .gitignore found", advice="Exclude secrets, local environments and generated files."))
    if not odoo and not any((root / n).exists() for n in ("tests", "test", "__tests__")):
        results.append(finding("missing-tests", "low", "No conventional test directory found", advice="Add automated tests."))
    if odoo:
        manifest = root / "__manifest__.py"
        if not manifest.is_file():
            results.append(finding("odoo-missing-manifest", "medium", "Odoo module manifest not found", "__manifest__.py"))
        else:
            try:
                data = ast.literal_eval(manifest.read_text(encoding="utf-8-sig"))
                if not isinstance(data, dict): raise ValueError("Manifest is not a dictionary")
                if not data.get("license"):
                    results.append(finding("odoo-license-unspecified", "low", "Odoo manifest has no license", "__manifest__.py", advice="Declare the module license in its manifest."))
                if not data.get("depends"):
                    results.append(finding("odoo-dependencies-unspecified", "low", "Odoo manifest has no dependencies", "__manifest__.py", advice="Verify required Odoo modules and declare depends."))
            except (SyntaxError, ValueError, UnicodeError, OSError) as exc:
                results.append(finding("odoo-invalid-manifest", "medium", "Cannot parse Odoo manifest safely", "__manifest__.py", advice="Use a Python literal dictionary; dynamic expressions are not supported."))
        for csvfile in root.rglob("ir.model.access.csv"):
            if csvfile.is_symlink(): continue
            try:
                with csvfile.open(encoding="utf-8-sig", newline="") as fh:
                    for rownum, row in enumerate(csv.DictReader(fh), 2):
                        if not row.get("group_id:id", "").strip() and any(row.get(k, "0").strip() == "1" for k in ("perm_write", "perm_create", "perm_unlink")):
                            results.append(finding("odoo-broad-access", "medium", "Write/create/delete access without a group restriction; review intended permissions", csvfile.relative_to(root).as_posix(), rownum, "Restrict the group or document why access is intentionally broad."))
            except (OSError, UnicodeError, csv.Error): pass
    checks_run = ["repository-metadata", "credential-patterns"]
    if odoo:
        checks_run += ["odoo-manifest", "odoo-access-csv", "odoo-sudo-review", "odoo-python-dangerous-calls", "odoo-xml-parse"]
    limitations = ["Static heuristic checks only; no runtime behavior or dependency CVE analysis.",
                   "A clean report is not proof that the repository is secure or accessible."]
    if odoo:
        limitations.append("No complete Odoo ACL/record-rule analysis or browser-based accessibility tests.")
    files_scanned = 0
    for path in sorted(root.rglob("*")):
        if any(part in SKIP_DIRS for part in path.relative_to(root).parts): continue
        if path.is_symlink() or not path.is_file() or path.suffix.lower() not in SOURCE_SUFFIXES: continue
        try:
            if path.stat().st_size > MAX_BYTES: continue
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeError): continue
        files_scanned += 1
        rel = path.relative_to(root).as_posix()
        for line_no, line in enumerate(content.splitlines(), 1):
            if odoo and path.suffix == ".py" and re.search(r"\.sudo\s*\(", line) and not line.lstrip().startswith("#"):
                results.append(finding("odoo-sudo-review", "low", "sudo() bypasses access controls; manual review recommended", rel, line_no, "Confirm elevated privileges are necessary and scope is minimal."))
            if odoo and path.suffix == ".py" and not line.lstrip().startswith("#"):
                if re.search(r"\b(?:eval|exec)\s*\(", line):
                    results.append(finding("odoo-dynamic-execution-review", "medium", "Dynamic Python execution requires manual review", rel, line_no, "Avoid eval/exec with untrusted input; prefer explicit parsing and allowlists."))
                if re.search(r"\b(?:subprocess\.(?:run|Popen|call)|os\.system)\s*\(", line):
                    results.append(finding("odoo-process-execution-review", "medium", "Process execution requires manual review", rel, line_no, "Use fixed command arguments, avoid shell=True and validate inputs."))
                if re.search(r"\b(?:request\.env|self\.env)\.cr\.execute\s*\(", line):
                    results.append(finding("odoo-raw-sql-review", "low", "Direct SQL requires manual review", rel, line_no, "Use parameterized queries and verify access rules."))
            for code, pattern, severity, advice in PATTERNS:
                if pattern.search(line):
                    results.append(finding(code, severity, "Potential exposed credential (value redacted)", rel, line_no, advice))
    if odoo:
        import xml.etree.ElementTree as ET
        for xmlfile in root.rglob("*.xml"):
            if xmlfile.is_symlink() or any(p in SKIP_DIRS for p in xmlfile.relative_to(root).parts):
                continue
            try:
                if xmlfile.stat().st_size > MAX_BYTES:
                    continue
                ET.parse(xmlfile)
            except ET.ParseError as exc:
                results.append(finding("odoo-invalid-xml", "medium", "XML is not well-formed", xmlfile.relative_to(root).as_posix(), exc.position[0], "Fix the XML syntax and validate the Odoo view separately."))
            except (OSError, UnicodeError):
                pass
    counts = {sev: sum(f["severity"] == sev for f in results) for sev in ("high", "medium", "low")}
    return {"tool": "repomedic", "version": "0.3.0", "profile": "odoo" if odoo else "generic", "root": str(root), "files_scanned": files_scanned, "summary": counts, "findings": results, "checks_run": checks_run, "limitations": limitations}

def html_report(report: dict) -> str:
    from html import escape
    e = lambda value: escape(str(value), quote=True)
    rows = "".join("<tr>" + "".join(f"<td>{e(f.get(k, ''))}</td>" for k in ("severity", "id", "path", "line", "message", "advice")) + "</tr>" for f in report["findings"])
    if not rows:
        rows = '<tr><td colspan="6">No findings from the checks executed. This is not a security certification.</td></tr>'
    checks = "".join(f"<li>{e(x)}</li>" for x in report.get("checks_run", []))
    limits = "".join(f"<li>{e(x)}</li>" for x in report.get("limitations", []))
    return ("<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
            "<title>RepoMedic audit</title><style>body{font:1rem system-ui;max-width:75rem;margin:auto;padding:1.5rem;line-height:1.6}"
            "a:focus-visible{outline:3px solid currentColor;outline-offset:3px}table{border-collapse:collapse;width:100%}"
            "th,td{border:1px solid #777;padding:.5rem;text-align:left}th{background:#eee}"
            ".scroll{overflow-x:auto}@media(prefers-color-scheme:dark){body{background:#151515;color:#eee}th{background:#333}}</style></head>"
            "<body><a href=\"#main\">Skip to report</a><main id=\"main\"><h1>RepoMedic audit</h1>"
            f"<p>Profile: {e(report.get('profile', 'unknown'))}. Files scanned: {e(report['files_scanned'])}. "
            f"Findings: {len(report['findings'])}.</p>"
            f"<h2>Checks executed</h2><ul>{checks}</ul><h2>Limitations</h2><ul>{limits}</ul>"
            "<h2>Findings</h2><div class=\"scroll\" role=\"region\" aria-label=\"Findings table\" tabindex=\"0\">"
            "<table><caption>Repository findings</caption><thead><tr>"
            "<th scope=\"col\">Severity</th><th scope=\"col\">Check</th><th scope=\"col\">File</th>"
            "<th scope=\"col\">Line</th><th scope=\"col\">Description</th><th scope=\"col\">Recommendation</th>"
            f"</tr></thead><tbody>{rows}</tbody></table></div></main></body></html>")
