# dependency-review-gate

Opinionated PR gate for dependency vulnerabilities and license compliance. More actionable than the default `dependency-review-action` — configurable severity thresholds, license policy enforcement, CVE ignore lists with audit trail, and a PR comment that tells the developer exactly what to fix.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `token` | Yes | — | GitHub token |
| `repo` | Yes | — | Repository in `owner/repo` format |
| `base_sha` | Yes | — | Base commit SHA (`github.event.pull_request.base.sha`) |
| `head_sha` | Yes | — | Head commit SHA (`github.event.pull_request.head.sha`) |
| `pr_number` | No | — | PR number for posting comments |
| `fail_on_severity` | No | `high` | Minimum severity to fail on: `critical`, `high`, `medium`, `low` |
| `allow_licenses` | No | — | Comma-separated SPDX identifiers that are allowed (mutually exclusive with `deny_licenses`) |
| `deny_licenses` | No | — | Comma-separated SPDX identifiers that are blocked |
| `ignore_cves` | No | — | Comma-separated CVE/GHSA IDs to ignore (logged in PR comment) |
| `comment_on_pr` | No | `true` | Post a summary comment on the PR |

## Usage

### Standard PR gate

```yaml
- uses: cschooley/ghas-actions/actions/dependency-review-gate@main
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    repo: ${{ github.repository }}
    base_sha: ${{ github.event.pull_request.base.sha }}
    head_sha: ${{ github.event.pull_request.head.sha }}
    pr_number: ${{ github.event.pull_request.number }}
```

### With license policy and CVE ignore list

```yaml
- uses: cschooley/ghas-actions/actions/dependency-review-gate@main
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    repo: ${{ github.repository }}
    base_sha: ${{ github.event.pull_request.base.sha }}
    head_sha: ${{ github.event.pull_request.head.sha }}
    pr_number: ${{ github.event.pull_request.number }}
    fail_on_severity: high
    deny_licenses: GPL-2.0, GPL-3.0, AGPL-3.0
    ignore_cves: GHSA-xxxx-yyyy-zzzz
```

See [examples/pr-gate.yml](examples/pr-gate.yml) for a complete workflow.

## PR Comment

When violations are found, the action posts a table to the PR:

| Package | Version | Ecosystem | Severity | CVE / Advisory | License | Reason |
|---|---|---|---|---|---|---|
| `lodash` | 4.17.20 | npm | high | GHSA-xxxx | MIT | vulnerability (high) |
| `left-pad` | 1.3.0 | npm | — | — | WTFPL | denied license |

Ignored CVEs are listed separately for audit purposes.

## License Checking

`allow_licenses` and `deny_licenses` are mutually exclusive:

- **`deny_licenses`** — block any added package with a listed license
- **`allow_licenses`** — block any added package whose license is NOT on the list

License checking is additive to vulnerability checking — a package with a denied license fails regardless of whether it has a vulnerability.

## Required Token Scopes / Permissions

```yaml
permissions:
  contents: read      # read dependency graph
  pull-requests: write  # post PR comment
```

## Trigger / Cost

This action only makes sense on `pull_request` — it needs a base and head SHA to compare. It makes GitHub API calls only (no local scanning) and completes in seconds. Safe to run on every PR with no cost concern.

```yaml
on:
  pull_request:
    branches: [main]
```

See [docs/workflow-triggers.md](../../docs/workflow-triggers.md) for broader trigger strategy guidance.

## Known Limitations

- Only evaluates **added** dependencies, not removed or updated ones
- Requires the dependency graph to be enabled on the repository
- License data depends on what GitHub has indexed — unknown licenses are not flagged
