#!/usr/bin/env python3
import base64
import os
import sys

import requests

CODEQL_LANGUAGE_MAP = {
    "Python": "python",
    "JavaScript": "javascript-typescript",
    "TypeScript": "javascript-typescript",
    "Java": "java-kotlin",
    "Kotlin": "java-kotlin",
    "C": "c-cpp",
    "C++": "c-cpp",
    "C#": "csharp",
    "Go": "go",
    "Ruby": "ruby",
    "Swift": "swift",
}


def parse_bool(value: str) -> bool:
    return value.strip().lower() in ("true", "1", "yes")


def codeql_workflow_content(language: str, config_path: str | None = None) -> str:
    config_line = f"\n          config-file: {config_path}" if config_path else ""
    return f"""name: CodeQL

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
          languages: {language}{config_line}
      - uses: github/codeql-action/autobuild@v3
      - uses: github/codeql-action/analyze@v3
        with:
          category: "/language:{language}"
"""


def paginate(session: requests.Session, url: str, params: dict) -> list[dict]:
    results = []
    while url:
        resp = session.get(url, params=params)
        if resp.status_code == 401:
            print("ERROR: Token is invalid or expired.", file=sys.stderr)
            sys.exit(1)
        if resp.status_code == 403:
            print(
                "ERROR: Token lacks required permissions. "
                "Org mode requires 'admin:org' scope.",
                file=sys.stderr,
            )
            sys.exit(1)
        if not resp.ok:
            print(f"ERROR: GitHub API returned {resp.status_code}: {resp.text}", file=sys.stderr)
            sys.exit(1)
        results.extend(resp.json())
        url = resp.links.get("next", {}).get("url")
        params = {}
    return results


def get_repo_info(session: requests.Session, owner: str, repo: str) -> dict | None:
    resp = session.get(f"https://api.github.com/repos/{owner}/{repo}")
    if not resp.ok:
        return None
    data = resp.json()
    security = data.get("security_and_analysis") or {}
    return {
        "language": data.get("language"),
        "default_branch": data.get("default_branch", "main"),
        "secret_scanning": security.get("secret_scanning", {}).get("status") == "enabled",
    }


def get_dependabot_state(session: requests.Session, owner: str, repo: str) -> dict:
    alerts = session.get(f"https://api.github.com/repos/{owner}/{repo}/vulnerability-alerts")
    updates = session.get(f"https://api.github.com/repos/{owner}/{repo}/automated-security-fixes")
    return {
        "dependabot_alerts": alerts.status_code == 204,
        "dependabot_updates": updates.ok and updates.json().get("enabled", False),
    }


def get_code_scanning_state(session: requests.Session, owner: str, repo: str) -> bool:
    resp = session.get(
        f"https://api.github.com/repos/{owner}/{repo}/contents/.github/workflows/codeql.yml"
    )
    return resp.status_code == 200


def get_current_state(session: requests.Session, owner: str, repo: str) -> dict | None:
    info = get_repo_info(session, owner, repo)
    if info is None:
        return None
    dep = get_dependabot_state(session, owner, repo)
    return {
        "dependabot_alerts": dep["dependabot_alerts"],
        "dependabot_updates": dep["dependabot_updates"],
        "secret_scanning": info["secret_scanning"],
        "code_scanning": get_code_scanning_state(session, owner, repo),
        "_language": info["language"],
        "_default_branch": info["default_branch"],
    }


def deploy_file(
    session: requests.Session,
    owner: str,
    repo: str,
    path: str,
    content: str,
    message: str,
    branch: str,
) -> None:
    existing = session.get(f"https://api.github.com/repos/{owner}/{repo}/contents/{path}")
    payload: dict = {
        "message": message,
        "content": base64.b64encode(content.encode()).decode(),
        "branch": branch,
    }
    if existing.ok:
        payload["sha"] = existing.json()["sha"]
    resp = session.put(
        f"https://api.github.com/repos/{owner}/{repo}/contents/{path}",
        json=payload,
    )
    if not resp.ok:
        raise RuntimeError(f"Failed to deploy {path}: {resp.status_code} {resp.text}")


def _enable_feature(
    session: requests.Session,
    owner: str,
    repo: str,
    feature: str,
    language: str | None,
    default_branch: str,
    code_scanning_config_content: str | None,
) -> None:
    if feature == "dependabot_alerts":
        resp = session.put(f"https://api.github.com/repos/{owner}/{repo}/vulnerability-alerts")
        if not resp.ok:
            raise RuntimeError(f"{resp.status_code}: {resp.text}")

    elif feature == "dependabot_updates":
        resp = session.put(f"https://api.github.com/repos/{owner}/{repo}/automated-security-fixes")
        if not resp.ok:
            raise RuntimeError(f"{resp.status_code}: {resp.text}")

    elif feature == "secret_scanning":
        resp = session.patch(
            f"https://api.github.com/repos/{owner}/{repo}",
            json={
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled"},
                    "secret_scanning_push_protection": {"status": "enabled"},
                }
            },
        )
        if not resp.ok:
            raise RuntimeError(f"{resp.status_code}: {resp.text}")

    elif feature == "code_scanning":
        codeql_lang = CODEQL_LANGUAGE_MAP.get(language) if language else None
        if not codeql_lang:
            raise RuntimeError(
                f"Language '{language}' is not supported by CodeQL. "
                f"Supported: {', '.join(sorted(CODEQL_LANGUAGE_MAP.keys()))}"
            )
        config_ref = None
        if code_scanning_config_content:
            config_ref = ".github/codeql-config.yml"
            deploy_file(
                session, owner, repo, config_ref,
                code_scanning_config_content, "Add CodeQL config", default_branch,
            )
        workflow = codeql_workflow_content(codeql_lang, config_ref)
        deploy_file(
            session, owner, repo, ".github/workflows/codeql.yml",
            workflow, "Add CodeQL workflow", default_branch,
        )


def enable_repo(
    session: requests.Session,
    owner: str,
    repo: str,
    desired: dict,
    dry_run: bool,
    code_scanning_config_content: str | None,
) -> dict[str, str]:
    print(f"\n{owner}/{repo}")
    current = get_current_state(session, owner, repo)
    if current is None:
        print(f"  ERROR: could not fetch repo info", file=sys.stderr)
        return {f: "error: could not fetch repo info" for f in desired}

    language = current.get("_language")
    default_branch = current.get("_default_branch", "main")
    results = {}

    for feature in ["dependabot_alerts", "dependabot_updates", "secret_scanning", "code_scanning"]:
        want = desired.get(feature, True)
        is_enabled = current.get(feature, False)

        if not want:
            print(f"  {feature}: {'enabled' if is_enabled else 'disabled'} → skip (not requested)")
            results[feature] = "skipped"
            continue

        if is_enabled:
            print(f"  {feature}: already enabled")
            results[feature] = "already enabled"
            continue

        if dry_run:
            print(f"  {feature}: disabled → would enable [DRY RUN]")
            results[feature] = "would enable"
            continue

        try:
            _enable_feature(session, owner, repo, feature, language, default_branch, code_scanning_config_content)
            print(f"  {feature}: disabled → enabled")
            results[feature] = "enabled"
        except RuntimeError as e:
            print(f"  {feature}: ERROR — {e}", file=sys.stderr)
            results[feature] = f"error: {e}"

    return results


def print_summary(all_results: dict[str, dict[str, str]]) -> None:
    print("\n--- Summary ---")
    totals: dict[str, int] = {"enabled": 0, "already enabled": 0, "would enable": 0, "skipped": 0, "error": 0}
    for features in all_results.values():
        for result in features.values():
            key = "error" if result.startswith("error") else result
            if key in totals:
                totals[key] += 1
    for status, count in totals.items():
        if count:
            print(f"  {status}: {count}")
    errors = [
        (repo, feature, result)
        for repo, features in all_results.items()
        for feature, result in features.items()
        if result.startswith("error")
    ]
    if errors:
        print("\nErrors:")
        for repo, feature, result in errors:
            print(f"  {repo} / {feature}: {result}", file=sys.stderr)


def main() -> None:
    token = os.environ.get("INPUT_TOKEN", "").strip()
    target = os.environ.get("INPUT_TARGET", "").strip()
    target_type = os.environ.get("INPUT_TARGET_TYPE", "").strip()
    enable_code_scanning = parse_bool(os.environ.get("INPUT_ENABLE_CODE_SCANNING", "true"))
    enable_secret_scanning = parse_bool(os.environ.get("INPUT_ENABLE_SECRET_SCANNING", "true"))
    enable_dependabot_alerts = parse_bool(os.environ.get("INPUT_ENABLE_DEPENDABOT_ALERTS", "true"))
    enable_dependabot_updates = parse_bool(os.environ.get("INPUT_ENABLE_DEPENDABOT_UPDATES", "true"))
    code_scanning_config_path = os.environ.get("INPUT_CODE_SCANNING_CONFIG", "").strip() or None
    dry_run = parse_bool(os.environ.get("INPUT_DRY_RUN", "false"))

    if not token:
        print("ERROR: 'token' input is required.", file=sys.stderr)
        sys.exit(2)
    if not target:
        print("ERROR: 'target' input is required.", file=sys.stderr)
        sys.exit(2)
    if target_type not in ("repo", "org"):
        print(f"ERROR: 'target_type' must be 'repo' or 'org', got '{target_type}'.", file=sys.stderr)
        sys.exit(2)
    if target_type == "repo" and target.count("/") != 1:
        print("ERROR: For target_type=repo, 'target' must be in owner/repo format.", file=sys.stderr)
        sys.exit(2)

    code_scanning_config_content = None
    if code_scanning_config_path:
        if not os.path.exists(code_scanning_config_path):
            print(f"ERROR: code_scanning_config file not found: {code_scanning_config_path}", file=sys.stderr)
            sys.exit(2)
        with open(code_scanning_config_path) as f:
            code_scanning_config_content = f.read()

    desired = {
        "code_scanning": enable_code_scanning,
        "secret_scanning": enable_secret_scanning,
        "dependabot_alerts": enable_dependabot_alerts,
        "dependabot_updates": enable_dependabot_updates,
    }

    session = requests.Session()
    session.headers.update({
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    })

    if dry_run:
        print("DRY RUN — no changes will be made\n")

    all_results: dict[str, dict[str, str]] = {}

    if target_type == "repo":
        owner, repo = target.split("/")
        all_results[target] = enable_repo(session, owner, repo, desired, dry_run, code_scanning_config_content)
    else:
        print(f"Fetching repos for org: {target}...")
        repos = paginate(session, f"https://api.github.com/orgs/{target}/repos", {"per_page": 100, "type": "all"})
        print(f"  {len(repos)} repo(s) found")
        for repo_data in repos:
            owner = repo_data["owner"]["login"]
            repo = repo_data["name"]
            result = enable_repo(session, owner, repo, desired, dry_run, code_scanning_config_content)
            all_results[f"{owner}/{repo}"] = result

    print_summary(all_results)

    if any(v.startswith("error") for features in all_results.values() for v in features.values()):
        sys.exit(1)


if __name__ == "__main__":
    main()
