# trivy-scanner

Run an [Aqua Trivy](https://trivy.dev) scan against a container image, filesystem, or IaC config and upload results to GitHub Advanced Security. Supports all three scan types with configurable severity thresholds, optional `--ignore-unfixed`, and a custom Trivy config file.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `target` | Yes | — | What to scan: image name (`python:3.11-slim`), directory path (`.`), or config path |
| `scan_type` | No | `fs` | `image`, `fs`, or `config` |
| `severity` | No | `HIGH` | Minimum severity to report: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW` — includes all levels above |
| `output_file` | No | `trivy-results.sarif` | Path to write SARIF output |
| `upload_to_ghas` | No | `true` | Upload SARIF to GitHub code scanning |
| `ignore_unfixed` | No | `false` | Skip vulnerabilities with no fix available |
| `trivy_config` | No | — | Path to a `trivy.yaml` config file |

## Usage

### Scan the repository filesystem

```yaml
- uses: cschooley/ghas-actions/actions/trivy-scanner@main
  with:
    target: .
    scan_type: fs
    severity: HIGH
```

### Scan a container image

```yaml
- uses: cschooley/ghas-actions/actions/trivy-scanner@main
  with:
    target: ${{ env.IMAGE_NAME }}:${{ github.sha }}
    scan_type: image
    severity: CRITICAL
    ignore_unfixed: 'true'
```

### Scan IaC / config files

```yaml
- uses: cschooley/ghas-actions/actions/trivy-scanner@main
  with:
    target: infrastructure/
    scan_type: config
    severity: HIGH
```

### With a Trivy config file

```yaml
- uses: cschooley/ghas-actions/actions/trivy-scanner@main
  with:
    target: .
    trivy_config: .trivy.yaml
```

See [examples/trivy-scan.yml](examples/trivy-scan.yml) for a complete workflow.

## Severity levels

Setting `severity: HIGH` reports `CRITICAL` and `HIGH` findings. The action always includes all levels at or above the threshold:

| Setting | Reports |
|---|---|
| `CRITICAL` | CRITICAL only |
| `HIGH` | CRITICAL, HIGH |
| `MEDIUM` | CRITICAL, HIGH, MEDIUM |
| `LOW` | CRITICAL, HIGH, MEDIUM, LOW |

## Trigger / Cost

Trivy `fs` scans are fast (typically under 30 seconds) and safe to run on every pull request. Image scans can take longer depending on image size — consider a `paths:` filter if your Dockerfile rarely changes.

```yaml
# fs scan — run on every PR, very low cost
on:
  pull_request:

# image scan — only when Docker-related files change
on:
  pull_request:
    paths:
      - 'Dockerfile'
      - 'docker-compose*.yml'
      - '.dockerignore'
```

See [docs/workflow-triggers.md](../../docs/workflow-triggers.md) for the full tradeoff guide.

## Required permissions

```yaml
permissions:
  security-events: write  # upload SARIF to code scanning
  contents: read
```

## Known limitations

- `config` scan type does not use `--ignore-unfixed` (no CVEs, so the flag is ignored)
- Trivy must be installed on the runner. The action installs it automatically via the official install script if not already present.
