# findings-exporter

Pull GitHub Advanced Security alerts (code scanning, secret scanning, Dependabot) via the GitHub API, normalize them to a common schema, and export to JSON or CSV.

Useful for feeding GHAS data into reporting pipelines, ticketing systems, audit workflows, or anything that needs a flat list of findings.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `token` | Yes | — | GitHub token with `security_events` scope |
| `repo` | Yes | — | Target repository in `owner/repo` format |
| `alert_types` | No | `code_scanning,secret_scanning,dependabot` | Comma-separated alert types to fetch |
| `state` | No | `open` | Alert state: `open`, `dismissed`, `fixed`, `all` |
| `output_format` | No | `json` | Output format: `json` or `csv` |
| `output_file` | No | `findings.json` | Path to write output |
| `severity_filter` | No | (none) | Minimum severity to include: `critical`, `high`, `medium`, `low` |

## Output Schema

Each finding is normalized to this schema regardless of alert type:

```json
{
  "source": "ghas",
  "alert_type": "code_scanning",
  "alert_id": 123,
  "composite_key": "ghas:code_scanning:owner/repo:123",
  "severity": "high",
  "state": "open",
  "rule_id": "py/sql-injection",
  "rule_name": "SQL Injection",
  "description": "...",
  "file": "src/app.py",
  "line": 42,
  "url": "https://github.com/...",
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z"
}
```

The `composite_key` (`source:alert_type:repo:alert_id`) is stable across exports and suitable for deduplication in downstream systems.

## Usage

### Minimal

```yaml
- uses: cschooley/ghas-actions/actions/findings-exporter@main
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    repo: ${{ github.repository }}
```

### Export high+ severity findings to CSV

```yaml
- uses: cschooley/ghas-actions/actions/findings-exporter@main
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    repo: ${{ github.repository }}
    severity_filter: high
    output_format: csv
    output_file: findings.csv
```

### Scheduled export with artifact upload

See [examples/export-on-schedule.yml](examples/export-on-schedule.yml).

## Required Token Scopes

- `security_events` — read code scanning and secret scanning alerts
- `public_repo` — sufficient for public repositories

The default `GITHUB_TOKEN` has `security_events` read access when GHAS is enabled on the repo. To export alerts from a different repo, use a PAT or GitHub App token with the appropriate scope.

## Known Limitations

- **Secret scanning file/line**: GitHub exposes file locations for secret scanning alerts via a separate `/locations` endpoint. This action does not fetch that data in v1; `file` and `line` are always `null` for secret scanning findings.
- **Secret scanning severity**: GitHub assigns no severity to secret scanning alerts. This action normalizes them to `critical`.
- **Single repo**: Fetches alerts for one repo at a time. For org-wide export, loop over repos in your workflow.
