# Enabling GHAS Features via GitHub CLI

All GitHub Advanced Security features can be enabled programmatically using `gh api` — no clicking through settings required. Useful for onboarding repos at scale or scripting a reproducible setup.

## Prerequisites

- `gh` CLI authenticated with a token that has `repo` scope
- For private repos: GitHub Advanced Security license on the org

## Dependabot Alerts

```bash
gh api --method PUT repos/OWNER/REPO/vulnerability-alerts
```

## Dependabot Security Updates

Requires Dependabot alerts to be enabled first.

```bash
gh api --method PUT repos/OWNER/REPO/automated-security-fixes
```

## Secret Scanning + Push Protection

```bash
gh api --method PATCH repos/OWNER/REPO \
  --input - <<'EOF'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
EOF
```

## Code Scanning (CodeQL)

Code scanning requires a workflow file in the repo. Push one via the API:

```bash
WORKFLOW=$(cat <<'EOF' | base64 -w 0
name: CodeQL

on:
  push:
    branches: ["main", "master"]
  pull_request:
    branches: ["main", "master"]
  schedule:
    - cron: '0 0 * * 0'

jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      actions: read
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: java-kotlin
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: "/language:java-kotlin"
EOF
)

gh api --method PUT repos/OWNER/REPO/contents/.github/workflows/codeql.yml \
  --field message="Add CodeQL workflow" \
  --field branch="BRANCH" \
  --field content="$WORKFLOW"
```

After pushing, trigger the first scan manually rather than waiting for the schedule:

```bash
gh workflow run codeql.yml --repo OWNER/REPO
```

## Verify Everything Is On

```bash
gh api repos/OWNER/REPO --jq '.security_and_analysis'
gh api repos/OWNER/REPO/vulnerability-alerts && echo "Dependabot alerts: enabled"
```

## All at Once (copy-paste block)

```bash
OWNER=your-org
REPO=your-repo
BRANCH=main

# Dependabot
gh api --method PUT repos/$OWNER/$REPO/vulnerability-alerts
gh api --method PUT repos/$OWNER/$REPO/automated-security-fixes

# Secret scanning
gh api --method PATCH repos/$OWNER/$REPO \
  --input - <<'EOF'
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
EOF

# CodeQL workflow
WORKFLOW=$(cat <<'YAML' | base64 -w 0
name: CodeQL
on:
  push:
    branches: ["main", "master"]
  pull_request:
    branches: ["main", "master"]
  schedule:
    - cron: '0 0 * * 0'
jobs:
  analyze:
    name: Analyze
    runs-on: ubuntu-latest
    permissions:
      security-events: write
      actions: read
      contents: read
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: java-kotlin
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: "/language:java-kotlin"
YAML
)

gh api --method PUT repos/$OWNER/$REPO/contents/.github/workflows/codeql.yml \
  --field message="Add CodeQL workflow" \
  --field branch="$BRANCH" \
  --field content="$WORKFLOW"

gh workflow run codeql.yml --repo $OWNER/$REPO
```
