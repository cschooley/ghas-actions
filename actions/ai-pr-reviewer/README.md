# ai-pr-reviewer

Claude-powered pull request security review. Analyzes PR diffs and either posts a markdown review comment or outputs findings as SARIF for upload to GitHub Advanced Security — putting AI-identified issues alongside CodeQL, Trivy, and ZAP in a single pane of glass.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `anthropic_api_key` | Yes | — | Anthropic API key (store as a repo secret) |
| `github_token` | Yes | — | GitHub token for reading the diff and posting comments |
| `repo` | Yes | — | Repository in `owner/repo` format |
| `pr_number` | Yes | — | Pull request number to review |
| `model` | No | `claude-haiku-4-5-20251001` | Claude model — Haiku for speed/cost, Sonnet for depth |
| `mode` | No | `comment` | `comment` (post PR review) or `sarif` (upload findings to GHAS) |
| `output_file` | No | `ai-review.sarif` | SARIF output path (used when `mode: sarif`) |
| `upload_to_ghas` | No | `true` | Upload SARIF to GitHub code scanning (when `mode: sarif`) |
| `fail_on_findings` | No | `false` | Exit 1 if findings are detected (advisory mode when false) |
| `focus` | No | `security` | Review focus: `security`, `general`, or `both` |

## Usage

### Comment mode — markdown review on the PR

```yaml
- uses: cschooley/ghas-actions/actions/ai-pr-reviewer@main
  with:
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    github_token: ${{ secrets.GITHUB_TOKEN }}
    repo: ${{ github.repository }}
    pr_number: ${{ github.event.pull_request.number }}
    mode: comment
    focus: security
```

### SARIF mode — findings in GitHub Security tab

```yaml
- uses: cschooley/ghas-actions/actions/ai-pr-reviewer@main
  with:
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    github_token: ${{ secrets.GITHUB_TOKEN }}
    repo: ${{ github.repository }}
    pr_number: ${{ github.event.pull_request.number }}
    mode: sarif
    upload_to_ghas: 'true'
    fail_on_findings: 'false'
```

In SARIF mode, Claude's findings become code scanning alerts alongside CodeQL, Trivy, and ZAP results — triaged, dismissed, and tracked in the same GitHub UI.

### Deeper analysis with Sonnet

```yaml
- uses: cschooley/ghas-actions/actions/ai-pr-reviewer@main
  with:
    anthropic_api_key: ${{ secrets.ANTHROPIC_API_KEY }}
    github_token: ${{ secrets.GITHUB_TOKEN }}
    repo: ${{ github.repository }}
    pr_number: ${{ github.event.pull_request.number }}
    model: claude-sonnet-4-6
    mode: sarif
```

See [examples/ai-review.yml](examples/ai-review.yml) for a complete workflow.

## Modes

### `comment`
Claude returns a structured markdown review posted directly as a PR comment. Good for team visibility and async review workflows.

### `sarif`
Claude's findings are structured as SARIF 2.1.0 and uploaded to GitHub code scanning. Each finding becomes a persistent alert that can be triaged, dismissed with a reason, and tracked over time — the same workflow as any other scanner.

## Cost

Requires your own `ANTHROPIC_API_KEY`. Anthropic provides a free tier ($5 credits on signup at [console.anthropic.com](https://console.anthropic.com)). At Haiku pricing, a typical PR diff costs fractions of a cent — $5 covers hundreds of reviews.

| Model | Speed | Cost | Best for |
|---|---|---|---|
| `claude-haiku-4-5-20251001` | Fast | ~$0.001/review | Routine PR review, high volume |
| `claude-sonnet-4-6` | Moderate | ~$0.01/review | Security-critical code, deeper analysis |

## Trigger / Cost

Run on `pull_request` only — this action needs a PR number to fetch the diff. Large diffs are automatically truncated to 3,000 lines with a warning.

```yaml
on:
  pull_request:
    branches: [main]
```

See [docs/workflow-triggers.md](../../docs/workflow-triggers.md) for broader trigger strategy guidance.

## Required permissions

```yaml
permissions:
  security-events: write   # upload SARIF (mode: sarif)
  contents: read
  pull-requests: write     # post comment (mode: comment)
```

## Known limitations

- Reviews added lines only (`+` lines in the diff) — does not analyze unchanged context
- SARIF mode relies on Claude returning structured JSON; if the model wraps output in a markdown code block, the action handles it automatically
- `fail_on_findings` in `comment` mode uses keyword detection (`**HIGH**`, `**CRITICAL**`, etc.) — SARIF mode is more reliable for automated gating
- Diffs larger than 3,000 lines are truncated; for very large PRs consider splitting changes or using `paths:` filters
