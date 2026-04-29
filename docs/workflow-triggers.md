# Workflow Trigger Configuration

## Default philosophy: shift left

All actions in this library default to `pull_request` triggers. Catching a vulnerability before it merges is categorically better than catching it after — the fix is smaller, the blast radius is zero, and the developer still has the context. **Shift as left as you can afford.**

That said, some scans are expensive. This guide covers the tradeoff patterns so you can make an informed choice for each action.

---

## Trigger patterns

### 1. Every pull request (default, recommended)

```yaml
on:
  pull_request:
    branches: [main]
```

Catches issues before merge. Every push to a PR branch re-runs the check. Best for fast scans (Trivy `fs`, dependency review, SARIF validation).

### 2. Pull request with path filters

Only fires when relevant files change. Reduces cost without sacrificing the pre-merge gate for the cases that matter.

```yaml
on:
  pull_request:
    paths:
      - 'src/**'
      - 'package*.json'
      - 'requirements*.txt'
      - 'Dockerfile'
      - '*.tf'
```

Good for: Trivy image scans (only when Dockerfile changes), IaC scans (only when `.tf` files change), CodeQL (only when source changes).

### 3. Push to main only

Runs after merge, not before. You lose the gate — issues land on main before they're caught — but you halve the number of scan runs on active repos.

```yaml
on:
  push:
    branches: [main]
```

Acceptable for: expensive scans where you trust your code review process, or as a complement to a lighter pre-merge check.

### 4. Scheduled (nightly or weekly)

Cheapest option for ongoing coverage. No PR feedback, but good for catching newly-disclosed CVEs against a fixed codebase between PRs.

```yaml
on:
  schedule:
    - cron: '0 2 * * 1'  # Mondays at 2am UTC
```

Good for: ZAP scans against a stable staging URL, Trivy image rescans of published images, org-wide findings exports.

### 5. Manual dispatch

```yaml
on:
  workflow_dispatch:
```

Use for full ZAP scans, SonarQube analysis, or any scan you want to run on demand without it blocking every PR.

---

## Per-action recommendations

| Action | Recommended trigger | Notes |
|---|---|---|
| `dependency-review-gate` | `pull_request` | Fast, only runs on PRs anyway (needs base/head SHA) |
| `sarif-validator` | `pull_request` | Near-instant, no reason not to gate every PR |
| `trivy-scanner` (fs) | `pull_request` | Fast — 15–30s typical |
| `trivy-scanner` (image) | `pull_request` + `paths: [Dockerfile]` | Only when image definition changes |
| `trivy-scanner` (config) | `pull_request` + `paths: ['**.tf', '**.yaml']` | Only when IaC changes |
| `zap-scanner` (baseline) | `pull_request` (if app starts fast) or `schedule` | Requires live app — evaluate startup cost |
| `zap-scanner` (full) | `workflow_dispatch` or dedicated security schedule | Never in automatic CI against production |
| `findings-exporter` | `schedule` | Reporting/audit use case, not a gate |
| `ghas-enablement` | `workflow_dispatch` | One-time or on-demand org setup |

---

## Combining triggers

Running a lightweight check on every PR and a deeper check on schedule is a common and effective pattern:

```yaml
# .github/workflows/security-fast.yml
on:
  pull_request:
    branches: [main]

jobs:
  trivy-fs:
    uses: cschooley/ghas-actions/actions/trivy-scanner@main
    with:
      target: .
      scan_type: fs
```

```yaml
# .github/workflows/security-deep.yml
on:
  schedule:
    - cron: '0 3 * * *'

jobs:
  trivy-image:
    uses: cschooley/ghas-actions/actions/trivy-scanner@main
    with:
      target: myorg/myapp:latest
      scan_type: image

  zap-baseline:
    uses: cschooley/ghas-actions/actions/zap-scanner@main
    with:
      target_url: 'https://staging.myapp.com'
```

---

## GitHub Actions billing notes

- **Public repos**: all Actions minutes are free.
- **Private repos**: minutes count against your plan. `ubuntu-latest` costs 1x; `windows-latest` costs 2x; `macos-latest` costs 10x.
- Scans that pull large Docker images (ZAP, SonarQube) add egress and startup time — schedule them rather than running per-commit.
- Use `concurrency:` to cancel in-progress runs when a new push arrives, so you're not paying for stale scans:

```yaml
concurrency:
  group: ${{ github.workflow }}-${{ github.ref }}
  cancel-in-progress: true
```
