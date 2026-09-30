# Tutorial: Zero to GHAS on a Clean Repo

This walkthrough takes you from a fresh repository to a fully instrumented GHAS setup. You'll add each action one at a time so you can see exactly what each one does before moving on.

**Time:** ~30 minutes  
**Prerequisites:** A GitHub account, a repo you own, GHAS enabled (free for public repos)

---

## 1. Set up your sandbox repo

If you don't have a repo to experiment with, create one now. A minimal Python or Node.js app works well — the language doesn't matter much since we're demonstrating the tooling, not auditing real code.

**Option A — fork the tutorial app:**

We recommend [flask-todo](https://github.com/tecladocode/flask-todo) or any small web app you can find on GitHub. Fork it into your account.

**Option B — create a minimal app from scratch:**

```bash
mkdir ghas-sandbox && cd ghas-sandbox
git init
echo "requests==2.28.0" > requirements.txt   # intentionally outdated
echo "flask==2.0.1" >> requirements.txt
git add . && git commit -m "initial"
gh repo create ghas-sandbox --public --source=. --push
```

The outdated packages will give us something real to find.

---

## 2. Enable GHAS

Go to your repo on GitHub:

```
Settings → Security → Code security and analysis → Enable all
```

For public repos, everything is free. For private repos on GitHub Enterprise, you'll need an Advanced Security license.

---

## 3. Add the dependency gate

This action runs on every PR and blocks merges that introduce vulnerable or unlicensed dependencies.

Create `.github/workflows/dependency-gate.yml`:

```yaml
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
          fail_on_severity: high
```

**Try it:** Create a branch, bump `requests` to a version with a known CVE, open a PR. You should see the check fail and a comment appear on the PR.

---

## 4. Add Trivy filesystem scan

This scans your repo's dependencies and source files for vulnerabilities and uploads findings to the Security tab.

Create `.github/workflows/trivy.yml`:

```yaml
name: Trivy

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read

jobs:
  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cschooley/ghas-actions/actions/trivy-scanner@main
        with:
          target: .
          scan_type: fs
          severity: HIGH
```

After your first run, check **Security → Code scanning alerts** in your repo. Trivy findings will appear there.

---

## 5. Add SARIF validation (optional but recommended)

If you're generating SARIF from multiple tools, add a validation step before upload to catch schema problems that cause silent failures in the GitHub UI.

```yaml
- uses: actions/checkout@v4

- name: Run Trivy
  run: |
    curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b ~/.local/bin
    trivy fs --format sarif --output trivy-results.sarif --severity CRITICAL,HIGH .

- uses: cschooley/ghas-actions/actions/sarif-validator@main
  with:
    sarif_file: trivy-results.sarif
    strict: false

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: trivy-results.sarif
```

---

## 6. Review your findings

Once your workflows have run:

1. **Security → Code scanning alerts** — Trivy findings, grouped by severity
2. **Security → Dependabot alerts** — if Dependabot is enabled, it runs independently
3. **Pull request checks** — dependency gate shows as a required status check

---

## What's next

- Try the [vulnerable app tutorial](tutorial-vulnerable.md) to see real DAST findings from ZAP
- Read [workflow-triggers.md](workflow-triggers.md) to tune when scans run
- Already have a repo in production? See the [adoption guide](tutorial-adoption.md) for rolling this out without disrupting your team
