---
marp: true
theme: default
paginate: true
style: |
  section {
    font-family: 'Segoe UI', system-ui, sans-serif;
  }
  section.lead h1 {
    font-size: 2.2em;
  }
  h1 { color: #1a7f37; }
  h2 { color: #0969da; }
  code { background: #f6f8fa; }
  table { font-size: 0.85em; }
  .columns { display: grid; grid-template-columns: 1fr 1fr; gap: 1em; }

  /* Retro filmstrip slide */
  section.filmstrip {
    background-color: #f5eedc;
    color: #2a1f0e;
    border-top: 28px solid #1a1208;
    border-bottom: 28px solid #1a1208;
    position: relative;
  }
  section.filmstrip::before {
    content: '◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼';
    display: block;
    position: absolute;
    top: -24px;
    left: 0; right: 0;
    color: #f5eedc;
    font-size: 0.55em;
    letter-spacing: 0.15em;
    text-align: center;
  }
  section.filmstrip::after {
    content: '◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼  ◼';
    display: block;
    position: absolute;
    bottom: -24px;
    left: 0; right: 0;
    color: #f5eedc;
    font-size: 0.55em;
    letter-spacing: 0.15em;
    text-align: center;
  }
  section.filmstrip h1,
  section.filmstrip h2 {
    color: #5c3a10;
    font-family: 'Courier New', monospace;
  }
  section.filmstrip .cycle {
    display: grid;
    grid-template-columns: 1fr 1fr 1fr 1fr 1fr;
    gap: 0.5em;
    text-align: center;
    margin-top: 1.2em;
    font-size: 0.85em;
  }
  section.filmstrip .phase {
    background: rgba(92,58,16,0.12);
    border: 1px solid #5c3a10;
    border-radius: 6px;
    padding: 0.5em 0.3em;
  }
  section.filmstrip .phase .emoji { font-size: 1.6em; display: block; }
  section.filmstrip .phase .label { font-weight: bold; font-family: 'Courier New', monospace; }
  section.filmstrip .phase .nist { font-size: 0.72em; color: #5c3a10; opacity: 0.8; }
  section.filmstrip .arrow {
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 1.4em;
    color: #5c3a10;
  }
---

<!-- _class: lead -->

# Ship Secure Code with GitHub Advanced Security

**A practical tour of GHAS for teams that are already shipping**

---

## Who this is for

- Teams using GitHub who want to shift security left
- AppSec engineers trying to embed tooling without slowing down developers  
- Anyone who has said: *"we should really add a dependency scanner to CI"*

**Not required:** a security background. This is developer tooling.

---

## What is GHAS?

GitHub Advanced Security is a set of security features built into GitHub:

| Feature | What it does |
|---|---|
| **Code scanning** | SAST — finds bugs and vulnerabilities in source code |
| **Secret scanning** | Detects committed credentials and API keys |
| **Dependabot** | Alerts on and auto-fixes vulnerable dependencies |
| **Dependency review** | Blocks PRs that introduce new vulnerable deps |
| **Security overview** | Org-wide dashboard across all repos |

**Free for public repos.** Enterprise license for private repos.

---

## The problem GHAS solves

```
Developer pushes code
    ↓
PR opens
    ↓
Code review (humans, looking for logic)
    ↓  ← security scanner would go here
PR merges to main
    ↓
Deploy to staging
    ↓
Pen test / SAST scan (if any)  ← security tools usually go here
    ↓
Finding! ... 3 weeks later, different context
```

**Moving the scanner up = cheaper fix, less context switching.**

---

## "But we have AI for that"

AI coding tools and security gates do different jobs — they're not competing.

| | AI assistant (Copilot, etc.) | GHAS + this library |
|---|---|---|
| **Knows about** | Patterns in training data | Live CVE/advisory databases |
| **Runs when** | Someone asks it to | Every PR, automatically |
| **Output** | Suggestion in an editor | Blocked merge + audit trail |
| **Covers** | Code being written now | All deps, past and future |

The more your team leans on AI to write code, the more you need systematic scanning — AI-generated code introduces vulnerabilities at a measurable rate.

**They're complementary. Copilot writes the code. GHAS gates what ships.**

---

## Compliance mapping

Automated, documented scanning isn't just good practice — it's audit evidence.

| Framework | Relevant control | What satisfies it |
|---|---|---|
| **NIST 800-53** | RA-5 Vulnerability Scanning | Trivy, ZAP on every PR |
| **NIST 800-53** | SA-11 Developer Testing | CodeQL, sarif-validator |
| **NIST 800-53** | CM-4 Impact Analyses | `dependency-review-gate` before merge |
| **NIST 800-53** | AU-12 Audit Records | SARIF uploads + `findings-exporter` |
| **NIST 800-218** | PW.8 / RV.1 / RV.2 | Full AppSec Cycle (previous slide) |
| **OWASP ASVS** | V10 Malicious Code | Trivy SCA |
| **OWASP ASVS** | V14 Configuration | Trivy `config` scan (IaC) |
| **HIPAA** §164.308(a)(8) | Evaluation — regular security assessment | Scheduled scans + findings export |
| **CJIS** 5.11 | Formal Audits | Timestamped SARIF trail, PR gate log |
| **SOC2** CC8.1 | Change management gate | PR blocked until scan passes |
| **SOC2** CC7.1 | System monitoring | `findings-exporter` → reporting pipeline |

*"Our AI reviewed it"* is not a control response. A timestamped gate with a documented finding record is.

---

<!-- _class: filmstrip -->

# The AppSec Cycle

<div class="cycle">
  <div class="phase">
    <span class="emoji">☀️</span>
    <span class="label">PREPARE</span>
    <span class="nist">NIST SSDF<br>PO.1 · PO.2 · PO.4</span>
  </div>
  <div class="arrow">→</div>
  <div class="phase">
    <span class="emoji">☁️</span>
    <span class="label">BUILD</span>
    <span class="nist">NIST SSDF<br>PW.1 · PW.5 · PW.6 · PW.7</span>
  </div>
  <div class="arrow">→</div>
  <div class="phase">
    <span class="emoji">🌧️</span>
    <span class="label">DETECT</span>
    <span class="nist">NIST SSDF<br>PW.8 · RV.1</span>
  </div>
</div>

<div class="cycle" style="margin-top:0.4em; grid-template-columns: 1fr 1fr; max-width: 55%; margin-left: auto; margin-right: auto;">
  <div class="phase">
    <span class="emoji">🌊</span>
    <span class="label">LEARN</span>
    <span class="nist">NIST SSDF<br>PO.5 · PS.1</span>
  </div>
  <div class="phase">
    <span class="emoji">🏔️</span>
    <span class="label">RESPOND</span>
    <span class="nist">NIST SSDF<br>RV.2 · RV.3</span>
  </div>
</div>

*It doesn't end. That's the point.*

---

<!-- _class: filmstrip -->

## The AppSec Cycle: what each phase means

| Phase | What happens | GHAS tooling |
|---|---|---|
| ☀️ **Prepare** | Define requirements, configure tooling, assign ownership | `ghas-enablement`, branch protection |
| ☁️ **Build** | Write code against secure patterns, code review gates | CodeQL, `dependency-review-gate` |
| 🌧️ **Detect** | Scanners find what humans miss | `trivy-scanner`, `zap-scanner`, `sarif-validator` |
| 🏔️ **Respond** | Triage, prioritize, remediate | GitHub Security tab, Dependabot PRs |
| 🌊 **Learn** | Update baselines, tune rules, improve posture | `findings-exporter`, `.trivyignore`, rules TSV |

*NIST SP 800-218 (SSDF) practice references on previous slide.*

---

## This library: four actions, one goal

All actions in `cschooley/ghas-actions` follow the same pattern:
- Composite actions (drop into any repo, no custom Docker image)
- Advisory mode — observe before you gate
- SARIF output → GitHub Security tab

| Action | Cycle Phase | What it scans |
|---|---|---|
| `dependency-review-gate` | 🌧️ Detect | New vulnerable/unlicensed deps in PRs |
| `trivy-scanner` | 🌧️ Detect | Images, filesystems, Terraform |
| `zap-scanner` | 🌧️ Detect | Running web applications |
| `sarif-validator` | 🌧️ Detect | SARIF schema — catch upload failures early |
| `findings-exporter` | 🌊 Learn | Export findings for reporting pipelines |
| `ghas-enablement` | ☀️ Prepare | Enable GHAS features across repos/orgs |

---

## Advisory mode

The biggest adoption blocker: *"we can't break our CI pipeline."*

Every action supports `fail_on_findings: false`:

```yaml
- uses: cschooley/ghas-actions/actions/dependency-review-gate@main
  with:
    token: ${{ secrets.GITHUB_TOKEN }}
    repo: ${{ github.repository }}
    base_sha: ${{ github.event.pull_request.base.sha }}
    head_sha: ${{ github.event.pull_request.head.sha }}
    fail_on_findings: 'false'    # ← advisory: runs, reports, never blocks
```

In advisory mode the check is **always green**. Findings appear in the PR comment and Security tab. You build awareness before you build friction.

---

## Advisory mode PR comment

When findings exist in advisory mode, the PR comment includes a GitHub-native callout:

> [!WARNING]
> Advisory mode — findings detected but check is non-blocking.

| Package | Severity | CVE | Reason |
|---|---|---|---|
| `lodash` | HIGH | GHSA-xxxx-yyyy | vulnerability |
| `left-pad` | — | — | denied license (WTFPL) |

Developers see this. They start asking questions. That's the goal.

---

## Dependency review gate

**What it catches:** new vulnerable dependencies introduced in a PR — before they merge.

```yaml
on:
  pull_request:
    branches: [main]

jobs:
  gate:
    steps:
      - uses: cschooley/ghas-actions/actions/dependency-review-gate@main
        with:
          token: ${{ secrets.GITHUB_TOKEN }}
          repo: ${{ github.repository }}
          base_sha: ${{ github.event.pull_request.base.sha }}
          head_sha: ${{ github.event.pull_request.head.sha }}
          pr_number: ${{ github.event.pull_request.number }}
          deny_licenses: 'GPL-2.0,GPL-3.0,AGPL-3.0'
          fail_on_severity: high
```

Combines **vulnerability checking** and **license policy** in one gate.

---

## Trivy scanner

**What it catches:** known CVEs in dependencies, OS packages, container images, and IaC misconfigurations.

```yaml
# Scan the filesystem on every PR
- uses: cschooley/ghas-actions/actions/trivy-scanner@main
  with:
    target: .
    scan_type: fs       # or: image, config
    severity: HIGH      # CRITICAL, HIGH, MEDIUM, LOW
    ignore_unfixed: 'true'
```

Findings go directly to **Security → Code scanning alerts** via SARIF upload.

`fs` scans finish in ~20 seconds. Easy to add to every PR.

---

## ZAP scanner (DAST)

**What it catches:** running application vulnerabilities — XSS, headers, injection, exposed endpoints.

```yaml
services:
  app:
    image: myorg/myapp:latest
    ports: ['8080:8080']

steps:
  - uses: cschooley/ghas-actions/actions/zap-scanner@main
    with:
      target_url: 'http://localhost:8080'
      scan_type: baseline     # passive only — safe for CI
      fail_on_warnings: 'false'
```

**Baseline** = passive scan, CI-safe. **Full** = active attacks — only against targets you own and have authorized.

---

## SARIF: the common language

All tools write SARIF. SARIF uploads to GitHub. GitHub shows everything in one place.

```
CodeQL ──────────────────────────┐
Trivy ───────────── SARIF ───────→ GitHub Security tab
ZAP ─────────────────────────────┘
```

You can also upload SARIF from tools you already use: Snyk, Semgrep, Checkmarx.
GHAS becomes the **pane of glass** regardless of what scans you run.

---

## The adoption playbook

*(☀️ → ☁️ → 🌧️ → 🏔️ → 🌊 → repeat)*

1. **Week 1** — ☀️ Prepare: enable GHAS, add all scans in advisory mode
2. **Week 2** — 🏔️ Respond: triage findings, build `.trivyignore`, `ignore_cves` list
3. **Week 3** — 🌊 Learn: scans run clean, team has seen the findings
4. **Week 4** — 🌧️ Detect (blocking): flip `dependency-review-gate`, add as required check
5. **Month 2** — flip Trivy to blocking
6. **Month 3** — add ZAP in advisory mode against staging

Key: **one gate at a time, after the noise is tuned out.**

---

## Try it yourself: choose your path

**Path 1 — Clean slate:** create a small app, add the actions, see green results.  
→ [docs/tutorial-clean.md](../tutorial-clean.md)

**Path 2 — Already shipping:** advisory mode rollout without disrupting your team.  
→ [docs/tutorial-adoption.md](../tutorial-adoption.md)

**Path 3 — See real findings:** fork Juice Shop or vulnado, watch DAST and SCA fire.  
→ [docs/tutorial-vulnerable.md](../tutorial-vulnerable.md)

---

## Live demo (optional)

*If presenting live, fork [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) and add the ZAP workflow from `tutorial-vulnerable.md`. The baseline scan runs in ~3 minutes and produces immediately legible web security findings.*

Suggested demo flow:
1. Show the workflow file (2 minutes)
2. Trigger the scan live or show a recorded run
3. Walk through a finding in the Security tab
4. Show the PR comment from `dependency-review-gate`
5. Toggle `fail_on_findings: false` → `true` and show the gate blocking

---

## Resources

- **This library:** `github.com/cschooley/ghas-actions`
- **NIST SP 800-218 (SSDF):** `csrc.nist.gov/publications/detail/sp/800-218/final`
- **GHAS docs:** `docs.github.com/en/code-security`
- **Trivy:** `trivy.dev`
- **OWASP ZAP:** `zaproxy.org`
- **SARIF spec:** `sarifweb.azurewebsites.net`
- **Juice Shop:** `github.com/juice-shop/juice-shop`
- **vulnado:** `github.com/ScaleSec/vulnado`

---

<!-- _class: lead -->

# Questions?

`github.com/cschooley/ghas-actions`

*To render this deck: install [Marp for VS Code](https://marketplace.visualstudio.com/items?itemName=marp-team.marp-vscode), open this file, click the preview icon.*
