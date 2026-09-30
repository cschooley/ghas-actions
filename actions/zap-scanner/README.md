# zap-scanner

Run an [OWASP ZAP](https://www.zaproxy.org/) DAST scan against a live web application and upload results to GitHub Advanced Security. Supports baseline (passive, CI-safe) and full (active, authorized targets only) scan modes. Converts ZAP's JSON report to SARIF 2.1.0 for upload.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `target_url` | Yes | — | URL of the running application to scan |
| `scan_type` | No | `baseline` | `baseline` (passive) or `full` (active — authorized targets only) |
| `output_file` | No | `zap-results.sarif` | Path to write SARIF output |
| `upload_to_ghas` | No | `true` | Upload SARIF to GitHub code scanning |
| `rules_file` | No | — | Path to a ZAP rules TSV file to tune alert levels (`PASS`/`WARN`/`FAIL`/`IGNORE`) |
| `fail_on_warnings` | No | `false` | Exit 1 on warning-level findings (ZAP exit code 1 or 2) as well as failures |

## Usage

### Baseline scan against a service started in the workflow

```yaml
services:
  app:
    image: myorg/myapp:latest
    ports:
      - 8080:8080

steps:
  - uses: cschooley/ghas-actions/actions/zap-scanner@main
    with:
      target_url: 'http://localhost:8080'
      scan_type: baseline
```

### With a rules file to tune alert levels

```yaml
- uses: cschooley/ghas-actions/actions/zap-scanner@main
  with:
    target_url: 'https://staging.myapp.com'
    rules_file: .zap/rules.tsv
    fail_on_warnings: 'true'
```

### Full scan (active — only against targets you own and have authorized)

```yaml
- uses: cschooley/ghas-actions/actions/zap-scanner@main
  with:
    target_url: 'https://staging.myapp.com'
    scan_type: full
```

See [examples/zap-scan.yml](examples/zap-scan.yml) for a complete workflow.

## ZAP exit codes

ZAP's automation framework uses a specific exit code scheme that differs from typical CI tools:

| Code | Meaning | Default action behavior |
|---|---|---|
| `0` | No alerts | Exit 0 |
| `1` | INFO-level alerts | Exit 0 (exit 1 if `fail_on_warnings: true`) |
| `2` | WARN-level alerts | Exit 0 (exit 1 if `fail_on_warnings: true`) |
| `3` | FAIL-level alerts | Exit 1 always |
| `4` | ZAP internal error | Exit 1 always |

Alert levels are configurable via a rules TSV file — you can promote a finding to `FAIL` or silence it with `IGNORE` per rule ID.

## Tuning with a rules file

Create a `.zap/rules.tsv` in your repo:

```tsv
10202	IGNORE	# Absence of Anti-CSRF Tokens — acceptable for this app
10038	FAIL	# Content Security Policy missing — must fix
```

Each line: `<pluginId>\t<level>\t# optional comment`. Levels: `PASS`, `IGNORE`, `WARN`, `FAIL`.

## Trigger / Cost

ZAP baseline scans require a live application — they can't run without a service to target. This makes them more expensive than static analysis: you need to start your app first.

```yaml
# Only run on PRs targeting main (not every branch push)
on:
  pull_request:
    branches: [main]

# Or on a schedule for staging — cheaper than per-PR
on:
  schedule:
    - cron: '0 2 * * *'  # nightly against staging
```

Full scans send active attack traffic and should **never** run in CI against production. Gate them behind manual approval or limit to dedicated security testing environments.

See [docs/workflow-triggers.md](../../docs/workflow-triggers.md) for the full tradeoff guide.

## Required permissions

```yaml
permissions:
  security-events: write  # upload SARIF to code scanning
  contents: read
```

Docker must be available on the runner. GitHub-hosted `ubuntu-latest` runners include Docker.

## Known limitations

- ZAP runs in a Docker container — the runner must have Docker available
- Scanning `localhost` targets requires the app to be reachable from inside the container; the action passes `--add-host=host.docker.internal:host-gateway` automatically
- Full scans can take 30+ minutes depending on the target's surface area
