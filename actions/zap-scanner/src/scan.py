#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile

VALID_SCAN_TYPES = {"baseline", "full"}
ZAP_IMAGE = "ghcr.io/zaproxy/zaproxy:stable"

RISK_TO_LEVEL = {"3": "error", "2": "warning", "1": "note", "0": "note"}
RISK_TO_SEVERITY = {"3": "8.9", "2": "5.0", "1": "2.0", "0": "0.0"}
HTML_TAG_RE = re.compile(r"<[^>]+>")


def parse_bool(value: str) -> bool:
    return value.strip().lower() in ("true", "1", "yes")


def strip_html(text: str) -> str:
    return HTML_TAG_RE.sub("", text).strip()


def convert_to_sarif(zap_data: dict) -> dict:
    rules: dict[str, dict] = {}
    results: list[dict] = []

    for site in zap_data.get("site", []):
        for alert in site.get("alerts", []):
            rule_id = str(alert.get("pluginid") or alert.get("alertRef") or "unknown")
            riskcode = str(alert.get("riskcode", "0"))

            if rule_id not in rules:
                rules[rule_id] = {
                    "id": rule_id,
                    "name": alert.get("alert", rule_id),
                    "shortDescription": {"text": alert.get("name", rule_id)},
                    "fullDescription": {"text": strip_html(alert.get("desc", ""))},
                    "help": {"text": strip_html(alert.get("solution", "No solution provided."))},
                    "properties": {
                        "security-severity": RISK_TO_SEVERITY.get(riskcode, "0.0"),
                        "tags": ["security", "dast"],
                    },
                }

            for instance in alert.get("instances", []):
                uri = instance.get("uri", site.get("@name", ""))
                method = instance.get("method", "")
                param = instance.get("param", "")
                msg_parts = [alert.get("name", rule_id)]
                if method:
                    msg_parts.append(f"Method: {method}")
                if param:
                    msg_parts.append(f"Parameter: {param}")

                results.append({
                    "ruleId": rule_id,
                    "level": RISK_TO_LEVEL.get(riskcode, "note"),
                    "message": {"text": " | ".join(msg_parts)},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": uri},
                                "region": {"startLine": 1},
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
                        "name": "ZAP",
                        "version": zap_data.get("@version", "unknown"),
                        "informationUri": "https://www.zaproxy.org",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }


def build_zap_cmd(scan_type: str, target_url: str, work_dir: str, use_rules: bool = False) -> list[str]:
    script = "zap-baseline.py" if scan_type == "baseline" else "zap-full-scan.py"
    cmd = [
        "docker", "run", "--rm",
        "--add-host=host.docker.internal:host-gateway",
        "-v", f"{work_dir}:/zap/wrk:rw",
        ZAP_IMAGE,
        script,
        "-t", target_url,
        "-J", "zap-report.json",
    ]
    if use_rules:
        cmd.extend(["-c", "rules.tsv"])
    return cmd


def run_zap(cmd: list[str]) -> int:
    return subprocess.run(cmd).returncode


def main() -> None:
    target_url = os.environ.get("INPUT_TARGET_URL", "").strip()
    scan_type = os.environ.get("INPUT_SCAN_TYPE", "baseline").strip().lower()
    output_file = os.environ.get("INPUT_OUTPUT_FILE", "zap-results.sarif").strip()
    rules_file = os.environ.get("INPUT_RULES_FILE", "").strip() or None
    fail_on_warnings = parse_bool(os.environ.get("INPUT_FAIL_ON_WARNINGS", "false"))

    if not target_url:
        print("ERROR: 'target_url' input is required.", file=sys.stderr)
        sys.exit(2)
    if scan_type not in VALID_SCAN_TYPES:
        print(
            f"ERROR: 'scan_type' must be one of: {', '.join(sorted(VALID_SCAN_TYPES))}. Got '{scan_type}'.",
            file=sys.stderr,
        )
        sys.exit(2)
    if rules_file and not os.path.exists(rules_file):
        print(f"ERROR: rules_file not found: {rules_file}", file=sys.stderr)
        sys.exit(2)

    if scan_type == "full":
        print("WARNING: full scan sends active attack traffic — only use against authorized targets.", file=sys.stderr)

    work_dir = tempfile.mkdtemp(prefix="zap-")
    try:
        if rules_file:
            shutil.copy(rules_file, os.path.join(work_dir, "rules.tsv"))

        cmd = build_zap_cmd(scan_type, target_url, work_dir, use_rules=rules_file is not None)
        print(f"Running ZAP {scan_type} scan: {target_url}")
        rc = run_zap(cmd)

        # Automation framework exit codes:
        # 0: no alerts, 1: INFO alerts, 2: WARN alerts, 3: FAIL alerts, 4: internal error
        if rc == 4:
            print("ERROR: ZAP encountered an internal error (exit code 4).", file=sys.stderr)
            sys.exit(1)

        json_path = os.path.join(work_dir, "zap-report.json")
        if not os.path.exists(json_path):
            print(
                "ERROR: ZAP did not produce a report. "
                "Check that the target URL is reachable and Docker is available.",
                file=sys.stderr,
            )
            sys.exit(1)

        with open(json_path) as f:
            zap_data = json.load(f)

        sarif = convert_to_sarif(zap_data)
        finding_count = len(sarif["runs"][0]["results"])
        print(f"Scan complete — {finding_count} finding(s). Writing SARIF to {output_file}")

        with open(output_file, "w") as f:
            json.dump(sarif, f, indent=2)

        if rc == 3:
            print("FAILED: ZAP reported failure-level findings.", file=sys.stderr)
            sys.exit(1)
        if rc in (1, 2) and fail_on_warnings:
            print("FAILED: ZAP reported alert-level findings and fail_on_warnings is true.", file=sys.stderr)
            sys.exit(1)

    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    sys.exit(0)


if __name__ == "__main__":
    main()
