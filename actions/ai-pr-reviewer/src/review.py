#!/usr/bin/env python3
import json
import os
import re
import sys
import urllib.error
import urllib.request

VALID_MODES = {"comment", "sarif"}
VALID_FOCUSES = {"security", "general", "both"}

SEVERITY_TO_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}
SEVERITY_TO_SCORE = {"CRITICAL": "9.5", "HIGH": "8.0", "MEDIUM": "5.0", "LOW": "2.0"}
SEVERITY_KEYWORDS = {"**critical**", "**high**", "**medium**", "**low**"}

MAX_DIFF_LINES = 3000


def parse_bool(value: str) -> bool:
    return value.strip().lower() in ("true", "1", "yes")


def truncate_diff(diff: str, max_lines: int = MAX_DIFF_LINES) -> tuple[str, bool]:
    lines = diff.splitlines()
    if len(lines) <= max_lines:
        return diff, False
    return "\n".join(lines[:max_lines]), True


def build_sarif_prompt(diff: str, focus: str) -> str:
    focus_instruction = {
        "security": "Focus exclusively on security vulnerabilities, weaknesses, and risks (OWASP Top 10, injection, auth, secrets, insecure deps, data exposure).",
        "general": "Focus on code quality, bugs, error handling, and maintainability issues.",
        "both": "Cover both security vulnerabilities (OWASP Top 10, injection, auth, secrets) and general code quality issues.",
    }[focus]

    return f"""You are an expert code reviewer. {focus_instruction}

Analyze the following pull request diff and identify issues in added lines only (lines starting with +).

Return ONLY valid JSON — no markdown, no explanation, just the JSON object:
{{
  "findings": [
    {{
      "rule_id": "short-kebab-slug",
      "rule_name": "Human Readable Rule Name",
      "severity": "HIGH",
      "file": "path/to/file.py",
      "line": 42,
      "description": "Clear description of the issue and why it matters.",
      "recommendation": "Specific, actionable fix."
    }}
  ],
  "summary": "One sentence overall assessment."
}}

severity must be one of: CRITICAL, HIGH, MEDIUM, LOW.
If no issues found, return {{"findings": [], "summary": "No issues found."}}.

Pull request diff:
{diff}"""


def build_comment_prompt(diff: str, focus: str) -> str:
    focus_instruction = {
        "security": "Focus on security vulnerabilities and risks: OWASP Top 10, injection flaws, authentication issues, hardcoded secrets, insecure dependencies, and sensitive data exposure.",
        "general": "Focus on code quality, potential bugs, missing error handling, and maintainability.",
        "both": "Cover security vulnerabilities (OWASP Top 10, secrets, injection, auth) and general code quality issues.",
    }[focus]

    return f"""You are an expert code reviewer. {focus_instruction}

Review the following pull request diff. Only comment on added lines (lines starting with +).

Structure your response as markdown:

## Summary
One sentence overall assessment.

## Findings
For each issue: **SEVERITY** label, `file:line`, clear description, specific recommendation.
Use **CRITICAL**, **HIGH**, **MEDIUM**, or **LOW** labels.
If no issues found, say so briefly — do not invent findings.

Pull request diff:
{diff}"""


def findings_to_sarif(findings: list, repo: str, pr_number: str) -> dict:
    rules: dict[str, dict] = {}
    results = []

    for f in findings:
        rule_id = str(f.get("rule_id") or "unknown")
        severity = str(f.get("severity", "MEDIUM")).upper()

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.get("rule_name", rule_id),
                "shortDescription": {"text": f.get("rule_name", rule_id)},
                "fullDescription": {"text": f.get("description", "")},
                "help": {"text": f.get("recommendation", "")},
                "properties": {
                    "security-severity": SEVERITY_TO_SCORE.get(severity, "5.0"),
                    "tags": ["security", "ai-review"],
                },
            }

        msg = f.get("description", "")
        rec = f.get("recommendation", "")
        text = f"{msg} — {rec}" if rec else msg

        results.append({
            "ruleId": rule_id,
            "level": SEVERITY_TO_LEVEL.get(severity, "warning"),
            "message": {"text": text},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": f.get("file", "unknown"),
                            "uriBaseId": "%SRCROOT%",
                        },
                        "region": {"startLine": max(1, int(f.get("line") or 1))},
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
                        "name": "Claude AI Reviewer",
                        "version": "1.0.0",
                        "informationUri": "https://github.com/cschooley/ghas-actions",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
                "properties": {
                    "pullRequest": f"https://github.com/{repo}/pull/{pr_number}",
                },
            }
        ],
    }


def fetch_pr_diff(token: str, repo: str, pr_number: str) -> str:
    url = f"https://api.github.com/repos/{repo}/pulls/{pr_number}"
    req = urllib.request.Request(
        url,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github.v3.diff",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    with urllib.request.urlopen(req) as resp:
        return resp.read().decode("utf-8")


def post_pr_comment(token: str, repo: str, pr_number: str, body: str) -> None:
    url = f"https://api.github.com/repos/{repo}/issues/{pr_number}/comments"
    data = json.dumps({"body": body}).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
            "X-GitHub-Api-Version": "2022-11-28",
        },
        method="POST",
    )
    with urllib.request.urlopen(req) as resp:
        if resp.status not in (200, 201):
            raise RuntimeError(f"GitHub API error: {resp.status}")


def call_claude(api_key: str, model: str, prompt: str) -> str:
    import anthropic
    client = anthropic.Anthropic(api_key=api_key)
    message = client.messages.create(
        model=model,
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def parse_sarif_response(response: str) -> dict:
    """Extract and parse JSON from Claude's response, handling markdown code blocks."""
    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", response, re.DOTALL)
    if match:
        return json.loads(match.group(1))
    raise ValueError("Response does not contain valid JSON")


def comment_has_findings(text: str) -> bool:
    lower = text.lower()
    return any(kw in lower for kw in SEVERITY_KEYWORDS)


def main() -> None:
    api_key = os.environ.get("INPUT_ANTHROPIC_API_KEY", "").strip()
    token = os.environ.get("INPUT_GITHUB_TOKEN", "").strip()
    repo = os.environ.get("INPUT_REPO", "").strip()
    pr_number = os.environ.get("INPUT_PR_NUMBER", "").strip()
    model = os.environ.get("INPUT_MODEL", "claude-haiku-4-5-20251001").strip()
    mode = os.environ.get("INPUT_MODE", "comment").strip().lower()
    output_file = os.environ.get("INPUT_OUTPUT_FILE", "ai-review.sarif").strip()
    fail_on_findings = parse_bool(os.environ.get("INPUT_FAIL_ON_FINDINGS", "false"))
    focus = os.environ.get("INPUT_FOCUS", "security").strip().lower()

    if not api_key:
        print("ERROR: 'anthropic_api_key' input is required.", file=sys.stderr)
        sys.exit(2)
    if not token:
        print("ERROR: 'github_token' input is required.", file=sys.stderr)
        sys.exit(2)
    if not repo:
        print("ERROR: 'repo' input is required.", file=sys.stderr)
        sys.exit(2)
    if not pr_number:
        print("ERROR: 'pr_number' input is required.", file=sys.stderr)
        sys.exit(2)
    if mode not in VALID_MODES:
        print(f"ERROR: 'mode' must be one of: {', '.join(sorted(VALID_MODES))}. Got '{mode}'.", file=sys.stderr)
        sys.exit(2)
    if focus not in VALID_FOCUSES:
        print(f"ERROR: 'focus' must be one of: {', '.join(sorted(VALID_FOCUSES))}. Got '{focus}'.", file=sys.stderr)
        sys.exit(2)

    print(f"Fetching diff for {repo}#{pr_number}...")
    try:
        diff = fetch_pr_diff(token, repo, pr_number)
    except urllib.error.HTTPError as e:
        print(f"ERROR: Failed to fetch PR diff: {e}", file=sys.stderr)
        sys.exit(1)

    diff, truncated = truncate_diff(diff)
    if truncated:
        print(f"WARNING: Diff truncated to {MAX_DIFF_LINES} lines.", file=sys.stderr)

    if not diff.strip():
        print("No diff content found. Nothing to review.")
        sys.exit(0)

    print(f"Sending diff to {model} (mode: {mode}, focus: {focus})...")
    prompt = build_sarif_prompt(diff, focus) if mode == "sarif" else build_comment_prompt(diff, focus)

    try:
        response = call_claude(api_key, model, prompt)
    except Exception as e:
        print(f"ERROR: Anthropic API call failed: {e}", file=sys.stderr)
        sys.exit(1)

    if mode == "sarif":
        try:
            data = parse_sarif_response(response)
        except (json.JSONDecodeError, ValueError):
            print("ERROR: Claude did not return valid JSON.", file=sys.stderr)
            print(response, file=sys.stderr)
            sys.exit(1)

        findings = data.get("findings", [])
        summary = data.get("summary", "")
        sarif = findings_to_sarif(findings, repo, pr_number)
        finding_count = len(findings)

        with open(output_file, "w") as f:
            json.dump(sarif, f, indent=2)

        print(f"Review complete — {finding_count} finding(s). SARIF written to {output_file}")
        if summary:
            print(f"Summary: {summary}")

        if fail_on_findings and finding_count > 0:
            print(f"FAILED: {finding_count} finding(s) found and fail_on_findings is true.", file=sys.stderr)
            sys.exit(1)

    else:
        try:
            post_pr_comment(token, repo, pr_number, response)
        except Exception as e:
            print(f"ERROR: Failed to post PR comment: {e}", file=sys.stderr)
            sys.exit(1)

        print(f"Review posted as PR comment on {repo}#{pr_number}")

        if fail_on_findings and comment_has_findings(response):
            print("FAILED: Findings detected and fail_on_findings is true.", file=sys.stderr)
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    main()
