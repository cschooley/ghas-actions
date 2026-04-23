#!/usr/bin/env python3
import csv
import json
import os
import sys

import requests

SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning", "note", "none"]
VALID_ALERT_TYPES = {"code_scanning", "secret_scanning", "dependabot"}
VALID_STATES = {"open", "dismissed", "fixed", "all"}
VALID_FORMATS = {"json", "csv"}


def severity_meets_threshold(severity: str | None, threshold: str | None) -> bool:
    if not threshold:
        return True
    sev = (severity or "").lower()
    if sev not in SEVERITY_ORDER:
        return True  # unknown severity: include conservatively
    thresh = threshold.lower()
    if thresh not in SEVERITY_ORDER:
        return True
    return SEVERITY_ORDER.index(sev) <= SEVERITY_ORDER.index(thresh)


def check_response(resp: requests.Response) -> None:
    if resp.status_code == 401:
        print(
            "ERROR: GitHub token is invalid or expired. "
            "Check your token at https://github.com/settings/tokens",
            file=sys.stderr,
        )
        sys.exit(1)
    if resp.status_code == 403:
        print(
            "ERROR: Token lacks required permissions. "
            "findings-exporter requires the 'security_events' scope "
            "(or 'public_repo' for public repos). "
            "Check your token scopes at https://github.com/settings/tokens",
            file=sys.stderr,
        )
        sys.exit(1)
    if resp.status_code == 404:
        print(
            "ERROR: Repository not found or GHAS is not enabled on this repo. "
            "Verify the repo exists and that GitHub Advanced Security is enabled "
            "under Settings → Security → Code security and analysis.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not resp.ok:
        print(f"ERROR: GitHub API returned {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(1)


def paginate(session: requests.Session, url: str, params: dict) -> list[dict]:
    results = []
    while url:
        resp = session.get(url, params=params)
        check_response(resp)
        results.extend(resp.json())
        url = resp.links.get("next", {}).get("url")
        params = {}
    return results


def state_param(alert_type: str, state: str) -> dict:
    if state == "all":
        return {}
    if alert_type == "secret_scanning":
        return {"state": "resolved" if state in ("dismissed", "fixed") else state}
    return {"state": state}


def normalize_code_scanning(alert: dict, repo: str) -> dict:
    rule = alert.get("rule") or {}
    location = (alert.get("most_recent_instance") or {}).get("location") or {}
    severity = rule.get("security_severity_level") or rule.get("severity")
    return {
        "source": "ghas",
        "alert_type": "code_scanning",
        "alert_id": alert["number"],
        "composite_key": f"ghas:code_scanning:{repo}:{alert['number']}",
        "severity": (severity or "unknown").lower(),
        "state": alert.get("state"),
        "rule_id": rule.get("id"),
        "rule_name": rule.get("name") or rule.get("description"),
        "description": rule.get("full_description") or rule.get("description"),
        "file": location.get("path"),
        "line": location.get("start_line"),
        "url": alert.get("html_url"),
        "created_at": alert.get("created_at"),
        "updated_at": alert.get("updated_at"),
    }


def normalize_secret_scanning(alert: dict, repo: str) -> dict:
    return {
        "source": "ghas",
        "alert_type": "secret_scanning",
        "alert_id": alert["number"],
        "composite_key": f"ghas:secret_scanning:{repo}:{alert['number']}",
        "severity": "critical",  # GitHub assigns no severity; leaked secrets are always critical
        "state": alert.get("state"),
        "rule_id": alert.get("secret_type"),
        "rule_name": alert.get("secret_type_display_name"),
        "description": None,
        "file": None,  # requires separate /locations API call, not fetched in v1
        "line": None,
        "url": alert.get("html_url"),
        "created_at": alert.get("created_at"),
        "updated_at": alert.get("updated_at"),
    }


def normalize_dependabot(alert: dict, repo: str) -> dict:
    advisory = alert.get("security_advisory") or {}
    dependency = alert.get("dependency") or {}
    return {
        "source": "ghas",
        "alert_type": "dependabot",
        "alert_id": alert["number"],
        "composite_key": f"ghas:dependabot:{repo}:{alert['number']}",
        "severity": (advisory.get("severity") or "unknown").lower(),
        "state": alert.get("state"),
        "rule_id": advisory.get("cve_id") or advisory.get("ghsa_id"),
        "rule_name": advisory.get("summary"),
        "description": advisory.get("description"),
        "file": dependency.get("manifest_path"),
        "line": None,
        "url": alert.get("html_url"),
        "created_at": alert.get("created_at"),
        "updated_at": alert.get("updated_at"),
    }


NORMALIZERS = {
    "code_scanning": normalize_code_scanning,
    "secret_scanning": normalize_secret_scanning,
    "dependabot": normalize_dependabot,
}


def fetch_alerts(session: requests.Session, repo: str, alert_type: str, state: str) -> list[dict]:
    url = f"https://api.github.com/repos/{repo}/{alert_type.replace('_', '-')}/alerts"
    params = {"per_page": 100, **state_param(alert_type, state)}
    raw = paginate(session, url, params)
    return [NORMALIZERS[alert_type](a, repo) for a in raw]


def write_output(findings: list[dict], output_format: str, output_file: str) -> None:
    fieldnames = [
        "source", "alert_type", "alert_id", "composite_key", "severity",
        "state", "rule_id", "rule_name", "description", "file", "line",
        "url", "created_at", "updated_at",
    ]
    if output_format == "csv":
        with open(output_file, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(findings)
    else:
        with open(output_file, "w") as f:
            json.dump(findings, f, indent=2)


def main() -> None:
    token = os.environ.get("INPUT_TOKEN", "").strip()
    repo = os.environ.get("INPUT_REPO", "").strip()
    alert_types_raw = os.environ.get("INPUT_ALERT_TYPES", "code_scanning,secret_scanning,dependabot")
    state = os.environ.get("INPUT_STATE", "open").strip()
    output_format = os.environ.get("INPUT_OUTPUT_FORMAT", "json").strip()
    output_file = os.environ.get("INPUT_OUTPUT_FILE", "findings.json").strip()
    severity_filter = os.environ.get("INPUT_SEVERITY_FILTER", "").strip().lower() or None

    if not token:
        print("ERROR: 'token' input is required.", file=sys.stderr)
        sys.exit(2)
    if not repo:
        print("ERROR: 'repo' input is required.", file=sys.stderr)
        sys.exit(2)
    if repo.count("/") != 1:
        print(
            "ERROR: 'repo' must be in owner/repo format (e.g. 'octocat/hello-world').",
            file=sys.stderr,
        )
        sys.exit(2)

    alert_types = [t.strip() for t in alert_types_raw.split(",") if t.strip()]
    invalid_types = [t for t in alert_types if t not in VALID_ALERT_TYPES]
    if invalid_types:
        print(
            f"ERROR: Unknown alert_types: {', '.join(invalid_types)}. "
            f"Valid values: {', '.join(sorted(VALID_ALERT_TYPES))}",
            file=sys.stderr,
        )
        sys.exit(2)

    if state not in VALID_STATES:
        print(
            f"ERROR: Unknown state '{state}'. Valid values: {', '.join(sorted(VALID_STATES))}",
            file=sys.stderr,
        )
        sys.exit(2)

    if output_format not in VALID_FORMATS:
        print(f"ERROR: Unknown output_format '{output_format}'. Valid values: json, csv", file=sys.stderr)
        sys.exit(2)

    if severity_filter and severity_filter not in SEVERITY_ORDER:
        print(
            f"ERROR: Unknown severity_filter '{severity_filter}'. "
            f"Valid values: {', '.join(SEVERITY_ORDER)}",
            file=sys.stderr,
        )
        sys.exit(2)

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })

    all_findings = []
    for alert_type in alert_types:
        print(f"Fetching {alert_type} alerts for {repo}...")
        alerts = fetch_alerts(session, repo, alert_type, state)
        print(f"  {len(alerts)} alert(s) found")
        all_findings.extend(alerts)

    if severity_filter:
        before = len(all_findings)
        all_findings = [f for f in all_findings if severity_meets_threshold(f["severity"], severity_filter)]
        print(f"Severity filter '{severity_filter}': {before} → {len(all_findings)} finding(s)")

    write_output(all_findings, output_format, output_file)
    print(f"Exported {len(all_findings)} finding(s) to {output_file} ({output_format})")


if __name__ == "__main__":
    main()
