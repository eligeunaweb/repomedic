# RepoMedic repository audit skill

Use this skill when asked to review a local code repository for baseline hygiene and potential secrets.

1. Confirm the intended directory and authorization to inspect it.
2. Run `repomedic <directory> --format json --output repomedic-report.json`.
3. Read the JSON and distinguish high/medium/low severity findings.
4. Explain that findings are heuristic; never echo credential values.
5. Suggest minimal patches, but request approval before changing files, committing, or opening a pull request.
6. Do not upload audit results without explicit permission.

Requires RepoMedic to be installed. This skill does not itself execute tools.
