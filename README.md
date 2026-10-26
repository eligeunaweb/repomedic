# RepoMedic 🩺

**Offline-first repository health checks.** Free, open source, no account or AI key required.

RepoMedic v0.1.0 is a small, working Python CLI. It checks basic repository hygiene and searches selected text files for **potential** exposed credentials. Findings are heuristics, not proof of compromise. No files are uploaded and no fixes are applied automatically.

## Quick start

Requires Python 3.10+.

```bash
python -m pip install -e .
repomedic .
repomedic . --format json --output audit.json
repomedic . --format html --output audit.html
repomedic . --fail-on-high
```

Run tests without extra dependencies:

```bash
PYTHONPATH=src python -m unittest discover -s tests -v
```

## What is checked

- Presence of README, LICENSE, `.gitignore` and a conventional tests directory.
- Potential GitHub tokens, AWS access key IDs and private-key headers in selected source/config files.
- JSON, HTML (accessible semantic table) and terminal output.
- Nonzero exit code when `--fail-on-high` is used and a high-severity finding is present.

## Limitations

This is an MVP, **not** a full vulnerability scanner, dependency auditor, or accessibility testing engine. It does not check git history, remote branches, package vulnerability databases or running websites. Files larger than 500 KiB, common generated folders, and binary/unknown file types are skipped. Scanning a repository does not replace specialist tools such as gitleaks, OSV-Scanner, or axe-core. Avoid uploading generated reports from private projects.

## Roadmap

- [ ] Optional integration with OSV-Scanner and gitleaks
- [ ] SARIF reports for GitHub code scanning
- [ ] Optional Playwright + axe-core accessibility checks
- [ ] Reusable GitHub Action
- [ ] Agent skill and guided, reviewable fixes

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Please open an issue before large changes. Report security vulnerabilities privately using [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).


## Odoo profile (v0.2.0)

```powershell
repomedic "C:\blind-reader-odoo\blind_reader" --profile odoo --format html --output blind-reader-audit.html
```

The `auto` profile detects `__manifest__.py` in the target root. Odoo checks include safe manifest parsing, broad ACL warnings, and `sudo()` review hints. Findings are heuristics, not confirmed vulnerabilities. No Docker access required. This tool does not execute the inspected code.


## Version 0.3.0 — Odoo review checks

Run `repomedic path/to/module --profile odoo --format html --output report.html`.

Checks include manifest syntax and metadata, broad ACL CSV rows, review markers for `sudo()`, `eval()`/`exec()`, process execution and raw SQL, XML well-formedness, and selected credential patterns. Findings are heuristic, not confirmed exploits. The HTML report lists the checks executed and limitations. It does not test Odoo runtime permissions, dependency vulnerabilities, or accessibility with a browser/screen reader.

For reproducible checks: `python -m pip install -e . pytest` and `python -m pytest`.

## Public release checklist

Before publishing: check licensing of any bundled samples, verify tests on Windows/Linux, and review security findings. Do not include private Odoo modules, credentials or audit output from private projects.
