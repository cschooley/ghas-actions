# ghas-actions

A library of production-ready GitHub Actions for embedding security into your GitHub workflows. Built around GitHub Advanced Security (GHAS) — developer-native, SARIF-first, and designed to shift findings left without breaking the teams that are already shipping.

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cschooley/ghas-actions/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cschooley/ghas-actions)

---

## Actions

| Action | Type | What it does |
|---|---|---|
| [dependency-review-gate](actions/dependency-review-gate/) | SCA | PR gate for vulnerable and unlicensed dependencies |
| [trivy-scanner](actions/trivy-scanner/) | SCA / IaC | Scan images, filesystems, and Terraform with Trivy |
| [zap-scanner](actions/zap-scanner/) | DAST | OWASP ZAP baseline/full scan against a live web app |
| [sarif-validator](actions/sarif-validator/) | Utility | Validate SARIF files before upload to catch silent failures |
| [findings-exporter](actions/findings-exporter/) | Reporting | Export GHAS alerts to JSON/CSV for downstream pipelines |
| [ghas-enablement](actions/ghas-enablement/) | Setup | Enable GHAS features on a repo or across an org |

All actions support **advisory mode** — observe findings without blocking PRs while you tune noise and build team awareness. Flip a single input to go blocking when you're ready.

---

## Quick start

### Drop a gate on dependency PRs

```yaml
# .github/workflows/dependency-gate.yml
name: Dependency Gate
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  gate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cschooley/ghas-actions/actions/dependency-review-gate@main
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          repo: ${{ github.repository }}
          base_sha: ${{ github.event.pull_request.base.sha }}
          head_sha: ${{ github.event.pull_request.head.sha }}
          pr_number: ${{ github.event.pull_request.number }}
```

### Scan your repo with Trivy on every PR

```yaml
# .github/workflows/trivy.yml
name: Trivy
on:
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cschooley/ghas-actions/actions/trivy-scanner@main
        with:
          target: .
          scan_type: fs
          severity: HIGH
```

---

## Advisory mode

Every action that can block a PR supports `fail_on_findings: false`. In advisory mode:

- The check always exits green
- Findings appear in the PR comment and **Security → Code scanning alerts**
- The gate never fires

Start here. Tune your config. Go blocking when the scans run clean.

```yaml
- uses: cschooley/ghas-actions/actions/dependency-review-gate@main
  with:
    # ...
    fail_on_findings: 'false'    # advisory — never blocks
```

---

## Included workflows

These workflows live in `.github/workflows/` and demonstrate the actions in use on this repo itself.

| Workflow | Trigger | Purpose |
|---|---|---|
| [codeql.yml](.github/workflows/codeql.yml) | push, PR, schedule | SAST via CodeQL |
| [codeql-advanced.yml](.github/workflows/codeql-advanced.yml) | push to main, schedule | Extended CodeQL with custom queries |
| [dependency-review.yml](.github/workflows/dependency-review.yml) | PR | Dependency gate |
| [trivy.yml](.github/workflows/trivy.yml) | push, PR, schedule | Trivy fs scan |
| [sbom.yml](.github/workflows/sbom.yml) | release | CycloneDX SBOM artifact |
| [scorecard.yml](.github/workflows/scorecard.yml) | push to main, schedule | OpenSSF Scorecard |

---

## Documentation

### Guides
- [Workflow trigger configuration](docs/workflow-triggers.md) — shift-left vs cost tradeoffs, trigger patterns per action

### Tutorials
- [Path 1: Clean slate](docs/tutorial-clean.md) — zero-to-GHAS on a fresh repo
- [Path 2: Established team](docs/tutorial-adoption.md) — advisory mode rollout without disrupting your pipeline
- [Path 3: Vulnerable app](docs/tutorial-vulnerable.md) — see real findings with Juice Shop, vulnado, or BrokenCrystals

### Presentations
- [OWASP Brown Bag deck](docs/presentations/ghas-brownbag.md) — Marp presentation for chapter talks and internal brown bags

### Deep dives
- [CodeQL customization](docs/codeql-customization.md)
- [Secret scanning patterns](docs/secret-scanning-patterns.md)
- [Enabling GHAS via CLI](docs/enabling-ghas-via-cli.md)

---

## Security

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities in this repo.
