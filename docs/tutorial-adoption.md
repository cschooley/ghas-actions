# Adoption Guide: Adding GHAS to a Repo That's Already Shipping

You have a working CI pipeline. People are merging code. You want to add security scanning without:

- Blocking PRs unexpectedly
- Dumping 200 open findings on your team overnight
- Fighting with your security team about what "done" looks like

This guide walks through a phased rollout using the advisory mode built into these actions.

---

## The core principle: observe before you gate

Every action in this library supports `fail_on_findings: false` (or equivalent). In advisory mode, the action:

- Runs the full scan
- Posts a PR comment or logs findings
- **Exits 0** — the check is green, the PR can merge

This lets you measure your baseline, tune your configuration, and build team awareness before you flip the gate on.

---

## Phase 1: Shadow mode (week 1–2)

Add all the scans you want as advisory-only. Nothing blocks. You're collecting data.

```yaml
# .github/workflows/security-advisory.yml
name: Security (advisory)

on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write
  security-events: write

jobs:
  dependency-check:
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
          fail_on_findings: 'false'        # advisory — never blocks

  trivy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: cschooley/ghas-actions/actions/trivy-scanner@main
        with:
          target: .
          severity: HIGH
```

After a week, look at the Security tab. You now know:

- How many existing findings you have (your baseline)
- Which findings are real vs noise
- Whether any single rule is responsible for most of the volume

---

## Phase 2: Triage and tune (week 2–4)

Before you gate anything, deal with the noise.

### Ignore known-acceptable findings

For the dependency gate, use `ignore_cves` for findings you've reviewed and accepted:

```yaml
ignore_cves: 'GHSA-xxxx-yyyy-zzzz, CVE-2023-12345'
```

Every ignored CVE is logged in the PR comment with the ID, so there's an audit trail.

### Set a severity threshold that fits your risk posture

Most teams start at `HIGH` and work down:

```yaml
fail_on_severity: high    # blocks on HIGH and CRITICAL
```

If you have a lot of medium-severity noise in a legacy codebase, start at `CRITICAL` and add `HIGH` in a later sprint.

### Handle existing findings debt

If you have hundreds of pre-existing Trivy findings, don't let them block new PRs. Use a `.trivyignore` file to acknowledge them:

```
# .trivyignore
CVE-2023-12345  # accepted risk, no fix available, reviewed 2026-04-28
```

The ignore file should be in version control and reviewed periodically.

---

## Phase 3: Flip the gate (when you're ready)

Once you've triaged the noise and your scans are running clean, change `fail_on_findings` to `true` and make the check required.

```yaml
fail_on_findings: 'true'    # now it blocks
```

Then go to **Settings → Branches → Branch protection rules** for `main` and add the check as a required status check. New PRs cannot merge without it passing.

Do this one action at a time — don't flip all gates simultaneously.

---

## Phase 4: Add DAST (if applicable)

If you have a web application, add ZAP baseline scanning. Because ZAP requires a live app, you'll typically scan against a staging environment rather than spinning up the app in CI.

Start in advisory mode:

```yaml
- uses: cschooley/ghas-actions/actions/zap-scanner@main
  with:
    target_url: 'https://staging.myapp.internal'
    scan_type: baseline
    fail_on_warnings: 'false'    # advisory until tuned
```

Use a ZAP rules file to silence findings that don't apply to your threat model, then promote the most critical rules to `FAIL`:

```tsv
# .zap/rules.tsv
10202	IGNORE	# CSRF not applicable — API-only, no browser session
10038	FAIL	# Content Security Policy — must fix before going blocking
```

---

## Handling the "we already have a scanner" conversation

You may have Snyk, Veracode, Checkmarx, or another tool already. GHAS doesn't replace them — it adds a free, native layer that developers interact with directly in GitHub without leaving their workflow. The two coexist:

- Existing tool: deep analysis, compliance reporting, SIEM integration
- GHAS: developer-facing PR feedback, shift-left gates, zero-friction triage in the GitHub UI

If your existing tool exports SARIF, you can upload its results to GHAS code scanning via `github/codeql-action/upload-sarif@v3`. Run `sarif-validator` first to catch schema issues before upload.

---

## NIST SP 800-218 (SSDF) alignment

If your organization needs to map this rollout to a framework, the phased approach above aligns directly to the [NIST Secure Software Development Framework](https://csrc.nist.gov/publications/detail/sp/800-218/final):

| Phase | SSDF Practice Group | Key Practices |
|---|---|---|
| ☀️ Prepare | **PO — Prepare the Organization** | PO.1 (define security requirements), PO.2 (implement tooling), PO.4 (assign responsibilities) |
| ☁️ Build | **PW — Produce Well-Secured Software** | PW.1 (design for security), PW.5 (secure coding), PW.6 (secure build config), PW.7 (code review) |
| 🌧️ Detect | **PW + RV** | PW.8 (test executable code), RV.1 (identify and confirm vulnerabilities) |
| 🏔️ Respond | **RV — Respond to Vulnerabilities** | RV.2 (assess, prioritize, remediate), RV.3 (root cause analysis) |
| 🌊 Learn | **PS + PO** | PS.1 (protect code integrity), PO.5 (maintain secure environments) |

The advisory → blocking progression maps to SSDF's emphasis on iterative improvement: establish a baseline (PO.1), instrument tooling (PO.2), measure (RV.1), then tighten controls (RV.2).

---

## Checklist

- [ ] Week 1: All scans running in advisory mode, team notified
- [ ] Week 2: Baseline findings documented, noise triaged
- [ ] Week 3: `.trivyignore` and `ignore_cves` in place, scans running clean
- [ ] Week 4: Flip first gate to blocking (start with `dependency-review-gate`)
- [ ] Month 2: Second gate blocking (Trivy)
- [ ] Month 3: DAST added in advisory, tuning in progress
- [ ] Ongoing: Review ignored CVEs quarterly, ratchet severity thresholds down
