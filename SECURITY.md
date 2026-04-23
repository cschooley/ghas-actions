# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| main    | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please use [GitHub Private Vulnerability Reporting](https://github.com/cschooley/ghas-actions/security/advisories/new) to disclose vulnerabilities confidentially.

You can expect:
- Acknowledgement within 48 hours
- A status update within 5 business days
- Credit in the advisory if desired

## Security Controls in This Repo

| Control | Status |
|---|---|
| CodeQL SAST scanning | Enabled on push and weekly |
| Secret scanning + push protection | Enabled |
| Dependency Review on PRs | Enabled |
| Dependabot auto-remediation | Enabled |
| OpenSSF Scorecard | Weekly |
| SBOM on release | Enabled |
| Branch protection (main) | Required reviews + status checks |
