# ghas-enablement

Enable GitHub Advanced Security features (code scanning, secret scanning, Dependabot alerts, Dependabot security updates) on a single repo or across an entire org. Idempotent — safe to run repeatedly.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `token` | Yes | — | GitHub token with repo admin or `admin:org` scope |
| `target` | Yes | — | Repo (`owner/repo`) or org name |
| `target_type` | Yes | — | `repo` or `org` |
| `enable_code_scanning` | No | `true` | Deploy a CodeQL workflow to enable code scanning |
| `enable_secret_scanning` | No | `true` | Enable secret scanning and push protection |
| `enable_dependabot_alerts` | No | `true` | Enable Dependabot alerts |
| `enable_dependabot_updates` | No | `true` | Enable Dependabot security updates |
| `code_scanning_config` | No | — | Path to a CodeQL config file to deploy alongside the workflow |
| `dry_run` | No | `false` | Report what would change without making any changes |

## Usage

### Single repo

```yaml
- uses: cschooley/ghas-actions/actions/ghas-enablement@main
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    target: ${{ github.repository }}
    target_type: repo
```

### Dry run before enabling org-wide

```yaml
- uses: cschooley/ghas-actions/actions/ghas-enablement@main
  with:
    token: ${{ secrets.ORG_ADMIN_TOKEN }}
    target: my-org
    target_type: org
    dry_run: true
```

### Enable with a custom CodeQL config

```yaml
- uses: cschooley/ghas-actions/actions/ghas-enablement@main
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    target: ${{ github.repository }}
    target_type: repo
    code_scanning_config: .github/codeql-config.yml
```

### Scheduled org-wide enforcement

See [examples/enable-org-wide.yml](examples/enable-org-wide.yml).

## Required Token Scopes

- **Repo mode**: `repo` scope (full control of private repos) or `public_repo` for public repos
- **Org mode**: `admin:org` scope

## Behavior

- Logs current state → desired state for each feature on each repo
- Org mode processes all repos and reports per-repo results — does not abort on a single repo failure
- Code scanning: detects the repo's primary language and deploys an appropriate CodeQL workflow. If the language isn't supported by CodeQL, that repo is skipped with an error and processing continues
- Secret scanning: also enables push protection

## Trigger / Cost

This action is a one-time or on-demand setup tool. Use `workflow_dispatch` rather than automatic triggers — you don't want it re-running on every push.

```yaml
on:
  workflow_dispatch:
    inputs:
      target:
        description: 'Repo (owner/repo) or org name'
        required: true
      dry_run:
        description: 'Dry run only'
        default: 'true'
```

See [docs/workflow-triggers.md](../../docs/workflow-triggers.md) for broader trigger strategy guidance.

## Known Limitations

- Code scanning support is limited to languages CodeQL supports: C/C++, C#, Go, Java/Kotlin, JavaScript/TypeScript, Python, Ruby, Swift
- Repos with unsupported languages will have code scanning skipped with an error
- Org mode iterates all repos — for large orgs this may take a while; rate limiting is handled automatically by GitHub's API
