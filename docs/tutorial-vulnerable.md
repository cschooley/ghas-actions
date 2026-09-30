# Tutorial: Real Findings with Vulnerable Apps

The best way to understand what these actions actually catch is to point them at an application with known vulnerabilities. This tutorial uses intentionally vulnerable apps so you can see real findings fire without waiting for a CVE in production code.

---

## Choose your target

| App | Stack | Best for | Docker? |
|---|---|---|---|
| [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) | Node.js | ZAP DAST, XSS, injection | Yes |
| [vulnado](https://github.com/ScaleSec/vulnado) | Java / Spring Boot | CodeQL SAST, Trivy SCA (real CVE deps) | Yes |
| [BrokenCrystals](https://github.com/NeuraLegion/brokencrystals) | Node.js / GraphQL | ZAP DAST, modern API vulns | Yes |
| [WebGoat](https://github.com/WebGoat/WebGoat) | Java / Spring | CodeQL SAST, training-focused | Yes |

Pick one based on which action you want to test. The examples below use **Juice Shop** (ZAP) and **vulnado** (Trivy + CodeQL).

---

## Path A: Juice Shop + ZAP (DAST)

### 1. Fork Juice Shop

Fork [OWASP Juice Shop](https://github.com/juice-shop/juice-shop) into your GitHub account and clone it.

### 2. Add the ZAP workflow

Create `.github/workflows/zap.yml` in your fork:

```yaml
name: ZAP DAST

on:
  push:
    branches: [main]
  workflow_dispatch:

permissions:
  security-events: write
  contents: read

jobs:
  zap:
    runs-on: ubuntu-latest
    services:
      juiceshop:
        image: bkimminich/juice-shop
        ports:
          - 3000:3000

    steps:
      - uses: actions/checkout@v4

      - name: Wait for Juice Shop to be ready
        run: |
          for i in $(seq 1 30); do
            curl -sf http://localhost:3000 && break
            sleep 3
          done

      - uses: cschooley/ghas-actions/actions/zap-scanner@main
        with:
          target_url: 'http://localhost:3000'
          scan_type: baseline
          upload_to_ghas: 'true'
          fail_on_warnings: 'false'    # advisory — we expect findings
```

### 3. Watch findings appear

Push to `main` or trigger manually via **Actions → ZAP DAST → Run workflow**. After the run:

- Go to **Security → Code scanning alerts**
- You'll see ZAP findings: missing security headers, XSS vectors, exposed endpoints
- Click any finding — you get the URL, HTTP method, parameter, and remediation guidance

### 4. Try blocking mode

Once you've seen the findings, try `fail_on_warnings: 'true'`. Open a PR — the ZAP check will now block it. This shows your team what the developer experience looks like when a DAST gate fires.

---

## Path B: vulnado + Trivy (SCA) + CodeQL (SAST)

vulnado is a Java Spring Boot app built with intentionally vulnerable dependencies. It ships with real CVEs in its `pom.xml` so Trivy's SCA scan produces genuine findings.

### 1. Fork vulnado

Fork [ScaleSec/vulnado](https://github.com/ScaleSec/vulnado) into your account.

### 2. Add Trivy scanning

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
          upload_to_ghas: 'true'
```

After the first run, you'll see CVEs from vulnado's outdated dependencies in **Security → Code scanning alerts** — things like Spring Framework RCE vulnerabilities that were intentionally left in.

### 3. Add CodeQL

vulnado contains SQL injection, command injection, and path traversal in its Java source. CodeQL will find them.

Create `.github/workflows/codeql.yml`:

```yaml
name: CodeQL

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

permissions:
  security-events: write
  contents: read
  actions: read

jobs:
  analyze:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: github/codeql-action/init@v3
        with:
          languages: java
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
```

CodeQL will find SQL injection via user-controlled input flowing into JDBC queries — exactly the kind of finding CodeQL excels at.

### 4. Compare tools

After both workflows run, compare the findings:

- **Trivy** finds: outdated libraries with known CVEs (supply chain risk)
- **CodeQL** finds: logic flaws and data flow vulnerabilities in the source (SAST)

They're complementary — neither catches everything the other finds.

---

## What to show your team

If you're using this for a demo or brown bag:

1. **Show the PR comment** from `dependency-review-gate` — it's the most immediately legible output for developers who aren't security-focused
2. **Show the Security tab** with findings from multiple tools — demonstrates consolidation in one place without a separate SIEM
3. **Show advisory mode → blocking mode** — the `fail_on_findings` toggle is the conversation starter for "how do we adopt this without disrupting our sprints"
4. **Show a finding getting dismissed** in the GitHub UI — developers can triage without leaving GitHub, and dismissals are audited

For a live demo, Juice Shop + ZAP is the most visually impressive because the DAST findings are web-familiar (XSS, headers, endpoints) and the SARIF output maps back to real URLs.

---

## Next steps

- Tune ZAP alerts with a rules TSV file to reduce noise — see the [zap-scanner README](../actions/zap-scanner/README.md)
- Suppress accepted Trivy findings with `.trivyignore`
- Read the [adoption guide](tutorial-adoption.md) for rolling this pattern out to a real production repo
