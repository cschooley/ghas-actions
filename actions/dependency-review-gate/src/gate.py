#!/usr/bin/env python3
import json
import os
import sys

import requests

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def severity_meets_threshold(severity: str | None, threshold: str) -> bool:
    sev = (severity or "").lower()
    if sev not in SEVERITY_ORDER or threshold not in SEVERITY_ORDER:
        return False
    return SEVERITY_ORDER.index(sev) <= SEVERITY_ORDER.index(threshold)


def parse_list(value: str) -> list[str]:
    return [v.strip() for v in value.split(",") if v.strip()]


def check_response(resp: requests.Response, context: str) -> None:
    if resp.status_code == 401:
        print(
            "ERROR: GitHub token is invalid or expired. "
            "Check your token at https://github.com/settings/tokens",
            file=sys.stderr,
        )
        sys.exit(1)
    if resp.status_code == 403:
        print(
            f"ERROR: Token lacks permissions for {context}. "
            "dependency-review-gate requires 'contents: read' and 'pull-requests: write'.",
            file=sys.stderr,
        )
        sys.exit(1)
    if resp.status_code == 404:
        print(
            f"ERROR: Not found: {context}. "
            "Ensure the dependency graph is enabled and this is running on a pull_request event.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not resp.ok:
        print(f"ERROR: GitHub API returned {resp.status_code} for {context}: {resp.text}", file=sys.stderr)
        sys.exit(1)


def get_dependency_changes(session: requests.Session, repo: str, base_sha: str, head_sha: str) -> list[dict]:
    url = f"https://api.github.com/repos/{repo}/dependency-graph/compare/{base_sha}...{head_sha}"
    resp = session.get(url)
    check_response(resp, url)
    return resp.json()


def evaluate_changes(
    changes: list[dict],
    fail_on_severity: str,
    allow_licenses: list[str],
    deny_licenses: list[str],
    ignore_cves: list[str],
) -> tuple[list[dict], list[dict]]:
    """Returns (violations, ignored) tuples."""
    violations = []
    ignored = []

    for change in changes:
        if change.get("change_type") != "added":
            continue

        package_name = change.get("name", "unknown")
        version = change.get("version", "unknown")
        ecosystem = change.get("ecosystem", "unknown")
        license_id = change.get("license") or "unknown"
        vulnerabilities = change.get("vulnerabilities") or []

        for vuln in vulnerabilities:
            severity = (vuln.get("severity") or "").lower()
            cve = vuln.get("advisory_ghsa_id") or vuln.get("advisory_summary", "")

            if cve in ignore_cves:
                ignored.append({
                    "package": package_name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "severity": severity,
                    "cve": cve,
                    "license": license_id,
                    "reason": "CVE ignored",
                })
                continue

            if severity_meets_threshold(severity, fail_on_severity):
                violations.append({
                    "package": package_name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "severity": severity,
                    "cve": cve,
                    "license": license_id,
                    "reason": f"vulnerability ({severity})",
                })

        if not vulnerabilities:
            license_violation = False
            if deny_licenses and license_id in deny_licenses:
                license_violation = True
            elif allow_licenses and license_id not in allow_licenses and license_id != "unknown":
                license_violation = True

            if license_violation:
                violations.append({
                    "package": package_name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "severity": None,
                    "cve": None,
                    "license": license_id,
                    "reason": "denied license",
                })

        # License check is additive — also flag vuln packages with denied licenses
        elif vulnerabilities:
            license_violation = False
            if deny_licenses and license_id in deny_licenses:
                license_violation = True
            elif allow_licenses and license_id not in allow_licenses and license_id != "unknown":
                license_violation = True

            if license_violation and not any(v["package"] == package_name and v["reason"] == "denied license" for v in violations):
                violations.append({
                    "package": package_name,
                    "version": version,
                    "ecosystem": ecosystem,
                    "severity": None,
                    "cve": None,
                    "license": license_id,
                    "reason": "denied license",
                })

    return violations, ignored


def build_comment(violations: list[dict], ignored: list[dict], passed: bool, advisory: bool = False) -> str:
    lines = []

    if passed:
        lines.append("## Dependency Review Gate: PASSED")
        lines.append("")
        lines.append("No vulnerabilities or license violations found in added dependencies.")
    else:
        lines.append("## Dependency Review Gate: FAILED")
        lines.append("")
        lines.append(f"{len(violations)} issue(s) found in added dependencies.")
        if advisory:
            lines.append("")
            lines.append("> [!WARNING]")
            lines.append("> Advisory mode — findings detected but check is non-blocking.")

    if violations:
        lines.append("")
        lines.append("### Violations")
        lines.append("")
        lines.append("| Package | Version | Ecosystem | Severity | CVE / Advisory | License | Reason |")
        lines.append("|---|---|---|---|---|---|---|")
        for v in violations:
            lines.append(
                f"| `{v['package']}` "
                f"| {v['version']} "
                f"| {v['ecosystem']} "
                f"| {v['severity'] or '—'} "
                f"| {v['cve'] or '—'} "
                f"| {v['license']} "
                f"| {v['reason']} |"
            )

    if ignored:
        lines.append("")
        lines.append("### Ignored (audit trail)")
        lines.append("")
        lines.append("| Package | Version | CVE | Reason |")
        lines.append("|---|---|---|---|")
        for i in ignored:
            lines.append(f"| `{i['package']}` | {i['version']} | {i['cve']} | {i['reason']} |")

    return "\n".join(lines)


def post_pr_comment(session: requests.Session, repo: str, pr_number: int, body: str) -> None:
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    resp = session.post(url, json={"body": body})
    if not resp.ok:
        print(f"WARNING: Failed to post PR comment: {resp.status_code} {resp.text}", file=sys.stderr)


def main() -> None:
    token = os.environ.get("INPUT_TOKEN", "").strip()
    repo = os.environ.get("INPUT_REPO", "").strip()
    base_sha = os.environ.get("INPUT_BASE_SHA", "").strip()
    head_sha = os.environ.get("INPUT_HEAD_SHA", "").strip()
    pr_number_raw = os.environ.get("INPUT_PR_NUMBER", "").strip()
    fail_on_severity = os.environ.get("INPUT_FAIL_ON_SEVERITY", "high").strip().lower()
    allow_licenses_raw = os.environ.get("INPUT_ALLOW_LICENSES", "").strip()
    deny_licenses_raw = os.environ.get("INPUT_DENY_LICENSES", "").strip()
    ignore_cves_raw = os.environ.get("INPUT_IGNORE_CVES", "").strip()
    comment_on_pr = os.environ.get("INPUT_COMMENT_ON_PR", "true").strip().lower() in ("true", "1", "yes")
    fail_on_findings = os.environ.get("INPUT_FAIL_ON_FINDINGS", "true").strip().lower() in ("true", "1", "yes")

    if not token:
        print("ERROR: 'token' input is required.", file=sys.stderr)
        sys.exit(2)
    if not repo or repo.count("/") != 1:
        print("ERROR: 'repo' must be in owner/repo format.", file=sys.stderr)
        sys.exit(2)
    if not base_sha:
        print("ERROR: 'base_sha' is required. Use ${{ github.event.pull_request.base.sha }}.", file=sys.stderr)
        sys.exit(2)
    if not head_sha:
        print("ERROR: 'head_sha' is required. Use ${{ github.event.pull_request.head.sha }}.", file=sys.stderr)
        sys.exit(2)
    if fail_on_severity not in SEVERITY_ORDER:
        print(f"ERROR: 'fail_on_severity' must be one of: {', '.join(SEVERITY_ORDER)}.", file=sys.stderr)
        sys.exit(2)

    allow_licenses = parse_list(allow_licenses_raw)
    deny_licenses = parse_list(deny_licenses_raw)
    ignore_cves = parse_list(ignore_cves_raw)
    pr_number = int(pr_number_raw) if pr_number_raw.isdigit() else None

    if allow_licenses and deny_licenses:
        print("ERROR: 'allow_licenses' and 'deny_licenses' are mutually exclusive.", file=sys.stderr)
        sys.exit(2)

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })

    print(f"Fetching dependency changes: {repo} {base_sha[:7]}...{head_sha[:7]}")
    changes = get_dependency_changes(session, repo, base_sha, head_sha)
    added = [c for c in changes if c.get("change_type") == "added"]
    print(f"  {len(added)} added dependency/dependencies to review")

    violations, ignored = evaluate_changes(changes, fail_on_severity, allow_licenses, deny_licenses, ignore_cves)
    passed = len(violations) == 0

    if ignored:
        print(f"  {len(ignored)} finding(s) ignored via ignore_cves")

    if violations:
        print(f"\nFAILED — {len(violations)} violation(s):")
        for v in violations:
            print(f"  {v['package']} {v['version']}: {v['reason']}")
    else:
        print("\nPASSED — no violations found")

    if comment_on_pr and pr_number:
        comment = build_comment(violations, ignored, passed, advisory=not fail_on_findings)
        post_pr_comment(session, repo, pr_number, comment)
        print(f"  PR comment posted on #{pr_number}")
    elif comment_on_pr and not pr_number:
        print("  WARNING: comment_on_pr is true but no PR number provided — skipping comment", file=sys.stderr)

    if not passed and fail_on_findings:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
