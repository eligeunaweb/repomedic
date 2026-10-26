# RepoMedic v0.3.0 — Release notes

RepoMedic is an offline-first, MIT-licensed Python CLI for repository health checks, with an Odoo module review profile.

## Highlights

- Scan local projects and Odoo modules without uploading source files.
- Produce terminal, JSON and HTML reports.
- Check repository hygiene and selected potential secret patterns.
- Odoo review checks for manifest metadata, broad access permissions, `sudo()`, dynamic execution, process execution, raw SQL, and XML well-formedness.
- Optional nonzero exit status for high-severity findings.
- Automated unit-test workflow configured for Python 3.10 and 3.12 on Ubuntu and Windows.

## Install

Requires Python 3.10+.

```powershell
git clone https://github.com/eligeunaweb/repomedic.git
cd repomedic
python -m pip install -e .
repomedic --help
```

## Example

```powershell
repomedic "C:\path\to\odoo_module" --profile odoo --format html --output report.html
```

## Important limitations

Findings are heuristic and require manual review. A report with zero findings is not a security guarantee. RepoMedic does not test running services, databases, Docker containers, Git history or dependency CVEs. Avoid publishing reports from private repositories.

## License

MIT.
