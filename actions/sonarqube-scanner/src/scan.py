#!/usr/bin/env python3
import json
import os
import sys

import requests

SEVERITY_ORDER = ["BLOCKER", "CRITICAL", "MAJOR", "MINOR", "INFO"]
SEVERITY_TO_LEVEL = {
    "BLOCKER": "error",
    "CRITICAL": "error",
    "MAJOR": "warning",
    "MINOR": "note",
    "INFO": "note",
}
SEVERITY_TO_SCORE = {
    "BLOCKER": "9.0",
    "CRITICAL": "7.5",
    "MAJOR": "5.0",
    "MINOR": "3.0",
    "INFO": "0.0",
}
PAGE_SIZE = 500


def severity_meets_threshold(severity: str, threshold: str) -> bool:
    sev = severity if severity in SEVERITY_ORDER else "INFO"
    return SEVERITY_ORDER.index(sev) <= SEVERITY_ORDER.index(threshold)


def check_response(resp: requests.Response) -> None:
    if resp.status_code == 401:
        print(
            "ERROR: SonarQube token is invalid or expired. "
            "Generate a new token under My Account > Security.",
            file=sys.stderr,
        )
        sys.exit(1)
    if resp.status_code == 403:
        print(
            "ERROR: Token lacks permission to browse this project's issues.",
            file=sys.stderr,
        )
        sys.exit(1)
    if resp.status_code == 404:
        print(
            "ERROR: Project not found. Verify 'project_key' (and 'organization' "
            "for SonarCloud) and that analysis has completed.",
            file=sys.stderr,
        )
        sys.exit(1)
    if not resp.ok:
        print(f"ERROR: SonarQube API returned {resp.status_code}: {resp.text}", file=sys.stderr)
        sys.exit(1)


def fetch_all_issues(
    session: requests.Session, host_url: str, project_key: str, organization: str | None
) -> tuple[list[dict], dict[str, str]]:
    issues: list[dict] = []
    components: dict[str, str] = {}
    page = 1
    while True:
        params = {"componentKeys": project_key, "ps": PAGE_SIZE, "p": page}
        if organization:
            params["organization"] = organization
        resp = session.get(f"{host_url}/api/issues/search", params=params)
        check_response(resp)
        data = resp.json()

        issues.extend(data.get("issues", []))
        for component in data.get("components", []):
            components[component["key"]] = component.get("path") or component["key"]

        paging = data.get("paging", {})
        total = paging.get("total", len(issues))
        page_size = paging.get("pageSize", PAGE_SIZE)
        if page * page_size >= total:
            break
        page += 1

    return issues, components


def convert_to_sarif(issues: list[dict], components: dict[str, str], host_url: str) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for issue in issues:
        rule_key = issue.get("rule", "unknown")
        severity = issue.get("severity", "INFO")
        message = issue.get("message", rule_key)

        if rule_key not in rules:
            rules[rule_key] = {
                "id": rule_key,
                "name": rule_key,
                "shortDescription": {"text": message},
                "helpUri": f"{host_url}/coding_rules?open={rule_key}&rule_key={rule_key}",
                "properties": {
                    "security-severity": SEVERITY_TO_SCORE.get(severity, "0.0"),
                    "tags": ["security", issue.get("type", "CODE_SMELL").lower()],
                },
            }

        component_key = issue.get("component", "")
        path = components.get(component_key, component_key)
        text_range = issue.get("textRange") or {}
        line = text_range.get("startLine") or issue.get("line") or 1

        results.append({
            "ruleId": rule_key,
            "level": SEVERITY_TO_LEVEL.get(severity, "note"),
            "message": {"text": message},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": path},
                        "region": {"startLine": line},
                    }
                }
            ],
        })

    return {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SonarQube",
                        "informationUri": "https://www.sonarsource.com",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def main() -> None:
    sonar_host_url = os.environ.get("INPUT_SONAR_HOST_URL", "https://sonarcloud.io").strip().rstrip("/")
    sonar_token = os.environ.get("INPUT_SONAR_TOKEN", "").strip()
    project_key = os.environ.get("INPUT_PROJECT_KEY", "").strip()
    organization = os.environ.get("INPUT_ORGANIZATION", "").strip() or None
    output_file = os.environ.get("INPUT_OUTPUT_FILE", "sonar-results.sarif").strip()
    severity_filter = os.environ.get("INPUT_SEVERITY_FILTER", "MAJOR").strip().upper()

    if not sonar_token:
        print("ERROR: 'sonar_token' input is required.", file=sys.stderr)
        sys.exit(2)
    if not project_key:
        print("ERROR: 'project_key' input is required.", file=sys.stderr)
        sys.exit(2)
    if severity_filter not in SEVERITY_ORDER:
        print(
            f"ERROR: 'severity_filter' must be one of: {', '.join(SEVERITY_ORDER)}. "
            f"Got '{severity_filter}'.",
            file=sys.stderr,
        )
        sys.exit(2)

    session = requests.Session()
    session.auth = (sonar_token, "")

    print(f"Fetching issues for project '{project_key}' from {sonar_host_url}...")
    issues, components = fetch_all_issues(session, sonar_host_url, project_key, organization)
    print(f"{len(issues)} issue(s) found")

    before = len(issues)
    issues = [i for i in issues if severity_meets_threshold(i.get("severity", "INFO"), severity_filter)]
    print(f"Severity filter '{severity_filter}': {before} -> {len(issues)} issue(s)")

    sarif = convert_to_sarif(issues, components, sonar_host_url)
    with open(output_file, "w") as f:
        json.dump(sarif, f, indent=2)
    print(f"Wrote SARIF to {output_file}")

    sys.exit(0)


if __name__ == "__main__":
    main()
