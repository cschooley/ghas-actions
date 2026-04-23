# ghas-actions

Production-ready GitHub Advanced Security (GHAS) workflows and configurations for securing software supply chains.

## What's Included

| Feature | Description |
|---|---|
| **CodeQL Analysis** | Automated SAST scanning for multiple languages with custom queries |
| **Secret Scanning** | Push protection + custom patterns to block leaked credentials |
| **Dependency Review** | Block PRs that introduce vulnerable or license-violating dependencies |
| **Dependabot** | Auto-remediation PRs for vulnerable dependencies |
| **SBOM Generation** | Software Bill of Materials output on every release |
| **Security Scorecard** | OpenSSF Scorecard CI badge for supply chain health |
| **Branch Protection** | Policy-as-code for enforcing required security checks |

## Workflow Reference

### Code Scanning

| File | Trigger | Purpose |
|---|---|---|
| [codeql.yml](.github/workflows/codeql.yml) | push, PR, schedule | SAST via CodeQL |
| [codeql-advanced.yml](.github/workflows/codeql-advanced.yml) | push to main, schedule | Extended CodeQL with custom queries |

### Supply Chain Security

| File | Trigger | Purpose |
|---|---|---|
| [dependency-review.yml](.github/workflows/dependency-review.yml) | PR | Block vulnerable/unlicensed deps |
| [sbom.yml](.github/workflows/sbom.yml) | release | Generate CycloneDX SBOM artifact |
| [scorecard.yml](.github/workflows/scorecard.yml) | push to main, schedule | OpenSSF Scorecard |

### Secret Detection

| File | Purpose |
|---|---|
| [.github/secret_scanning.yml](.github/secret_scanning.yml) | Custom secret scanning patterns |

## Quick Start

### 1. Enable GHAS on your repo

GHAS is free for public repos. For private repos, it requires GitHub Enterprise or an Advanced Security license.

```
Settings → Security → Code security and analysis → Enable all
```

### 2. Copy the workflows you need

```bash
cp .github/workflows/codeql.yml /your-repo/.github/workflows/
cp .github/workflows/dependency-review.yml /your-repo/.github/workflows/
cp .github/dependabot.yml /your-repo/.github/
```

### 3. Review and tune

- Adjust `language` matrix in `codeql.yml` to match your stack
- Update `fail-on-severity` in `dependency-review.yml` for your risk tolerance
- Add your license policy to `dependency-review.yml`

## Security Policy

See [SECURITY.md](SECURITY.md) for how to report vulnerabilities in this repo.

## Docs

- [CodeQL customization guide](docs/codeql-customization.md)
- [Secret scanning patterns](docs/secret-scanning-patterns.md)
- [Scorecard interpretation](docs/scorecard.md)

---

[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/cschooley/ghas-actions/badge)](https://securityscorecards.dev/viewer/?uri=github.com/cschooley/ghas-actions)
