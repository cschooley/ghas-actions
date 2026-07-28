# sonarqube-scanner

Pull [SonarQube](https://www.sonarsource.com/products/sonarqube/) / [SonarCloud](https://sonarcloud.io/) issues for a project via the SonarQube Web API and upload them to GitHub Advanced Security. Converts issues to SARIF 2.1.0 so findings show up in the Security tab alongside CodeQL.

This action does **not** run the SonarQube analysis itself — it queries results after a scan has already completed. Run `sonarsource/sonarqube-scan-action` (or the SonarScanner CLI) earlier in the same job, then use this action to pull the results into GHAS.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `sonar_host_url` | No | `https://sonarcloud.io` | SonarQube server URL |
| `sonar_token` | Yes | — | SonarQube authentication token |
| `project_key` | Yes | — | SonarQube project key |
| `organization` | No | — | SonarCloud organization (required for SonarCloud, omit for self-hosted) |
| `output_file` | No | `sonar-results.sarif` | Path to write SARIF output |
| `upload_to_ghas` | No | `true` | Upload SARIF to GitHub code scanning |
| `severity_filter` | No | `MAJOR` | Minimum severity to include: `BLOCKER`, `CRITICAL`, `MAJOR`, `MINOR`, `INFO` |

## Usage

### SonarCloud

```yaml
permissions:
  security-events: write
  contents: read

steps:
  - uses: actions/checkout@v4
    with:
      fetch-depth: 0

  - uses: sonarsource/sonarqube-scan-action@v4
    env:
      SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}

  - uses: cschooley/ghas-actions/actions/sonarqube-scanner@main
    with:
      sonar_token: ${{ secrets.SONAR_TOKEN }}
      project_key: my-org_my-project
      organization: my-org
```

### Self-hosted SonarQube

```yaml
- uses: cschooley/ghas-actions/actions/sonarqube-scanner@main
  with:
    sonar_host_url: https://sonarqube.internal.example.com
    sonar_token: ${{ secrets.SONAR_TOKEN }}
    project_key: my-project
    # organization omitted — self-hosted has no concept of organizations
```

See [examples/sonarqube-scan.yml](examples/sonarqube-scan.yml) for a complete workflow.

## Severity mapping

| SonarQube severity | SARIF level | security-severity |
|---|---|---|
| `BLOCKER` | `error` | `9.0` |
| `CRITICAL` | `error` | `7.5` |
| `MAJOR` | `warning` | `5.0` |
| `MINOR` | `note` | `3.0` |
| `INFO` | `note` | `0.0` |

`severity_filter` keeps issues at or above the given severity (e.g. `MAJOR` includes `MAJOR`, `CRITICAL`, and `BLOCKER`, but drops `MINOR` and `INFO`).

## Required permissions

```yaml
permissions:
  security-events: write  # upload SARIF to code scanning
  contents: read
```

## Known limitations

- Requires a completed SonarQube analysis — this action only reads results via `/api/issues/search`, it does not trigger a scan
- Only unresolved issues are returned (SonarQube's default `issues/search` behavior excludes resolved/closed issues)
- Rule descriptions in the SARIF output link to the SonarQube rule page (`helpUri`) rather than embedding the full rule text, to avoid an extra API call per unique rule
