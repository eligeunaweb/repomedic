# RepoMedic 🩺

**Offline-first repository health checker for Python projects and Odoo modules.**

RepoMedic v0.3.0 is a free, open-source command-line tool that scans local source files and produces text, JSON, or HTML reports. It does not require an account, cloud service, or AI API key. It does not change the inspected project.

> **Security notice:** Findings are heuristic review prompts, not verified vulnerabilities. Zero findings does not mean a project is secure. RepoMedic is not a substitute for specialist security scanners or a professional audit.

## Install from source

Requires Python 3.10 or newer.

```powershell
git clone https://github.com/eligeunaweb/repomedic.git
cd repomedic
python -m pip install -e .
repomedic --help
```

## Scan a repository

```powershell
repomedic . --format text
repomedic . --format json --output audit.json
repomedic . --format html --output audit.html
```

## Scan an Odoo module

```powershell
repomedic "C:\path\to\my_odoo_module" --profile odoo --format html --output odoo-audit.html
```

The `auto` profile recognizes an Odoo module when its root contains `__manifest__.py`. The `generic` profile performs repository hygiene checks.

Odoo checks include manifest syntax and metadata, broad access-control CSV permissions, review markers for `sudo()`, dynamic execution, process execution and raw SQL, XML well-formedness, and selected potential credential patterns. Not every risky use is a vulnerability, and not every vulnerability is detected.

## Run tests

```powershell
$env:PYTHONPATH = "src"
python -m unittest discover -s tests -v
```

On Linux/macOS:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## Accessibility

HTML reports use semantic headings, a captioned table, and labeled columns. Accessibility with particular screen readers and browsers has not yet been independently validated; feedback and reproducible issues are welcome.

## Scope and limitations

- Scans local files; does not scan running Odoo instances, Docker containers, or databases.
- Does not run the inspected application or automatically apply fixes.
- Does not inspect Git history or comprehensively analyze dependencies or known CVEs.
- May miss security problems or flag safe code for manual review.
- Do not publicly upload audit reports containing sensitive paths or snippets.

## Roadmap

- [ ] Expand Odoo security rules and synthetic test fixtures
- [ ] SARIF export and reusable GitHub Action
- [ ] Optional integration with established dependency and secret scanners
- [ ] More comprehensive accessibility testing and screen-reader validation
- [ ] Agent skill and reviewable fix suggestions

## Contributing and security

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md). Please report suspected vulnerabilities privately rather than opening public issues containing exploit details.

## License

MIT — see [LICENSE](LICENSE).
