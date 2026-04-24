#!/usr/bin/env python3
import json
import os
import re
import sys

SUPPORTED_VERSIONS = {"2.1.0"}
VALID_LEVELS = {"error", "warning", "note", "none"}
ABSOLUTE_PATH_RE = re.compile(r'^(/|[A-Za-z]:[/\\])')


def check(status: str, message: str) -> dict:
    return {"status": status, "message": message}


def validate_json(content: str) -> tuple[dict | None, dict]:
    try:
        return json.loads(content), check("pass", "Valid JSON")
    except json.JSONDecodeError as e:
        return None, check("fail", f"Invalid JSON: {e}")


def validate_top_level(sarif: dict) -> list[dict]:
    results = []
    version = sarif.get("version")
    if not version:
        results.append(check("fail", "Missing required field: 'version'"))
    elif version not in SUPPORTED_VERSIONS:
        results.append(check("fail", f"Unsupported SARIF version '{version}'. Supported: {', '.join(SUPPORTED_VERSIONS)}"))
    else:
        results.append(check("pass", f"Schema version: {version}"))

    if "runs" not in sarif:
        results.append(check("fail", "Missing required field: 'runs'"))
    elif not isinstance(sarif["runs"], list) or len(sarif["runs"]) == 0:
        results.append(check("fail", "'runs' must be a non-empty array"))
    else:
        results.append(check("pass", f"'runs' present ({len(sarif['runs'])} run(s))"))

    return results


def validate_run(run: dict, run_index: int) -> list[dict]:
    prefix = f"Run {run_index + 1}"
    results = []

    # tool.driver.name
    driver_name = run.get("tool", {}).get("driver", {}).get("name")
    if not driver_name:
        results.append(check("fail", f"{prefix}: missing tool.driver.name"))
    else:
        results.append(check("pass", f"{prefix}: tool.driver.name = '{driver_name}'"))

    # rules
    rules = run.get("tool", {}).get("driver", {}).get("rules") or []
    rule_ids = [r.get("id") for r in rules if r.get("id")]

    dupes = {rid for rid in rule_ids if rule_ids.count(rid) > 1}
    if dupes:
        results.append(check("fail", f"{prefix}: duplicate ruleIds: {', '.join(sorted(dupes))}"))
    else:
        results.append(check("pass", f"{prefix}: no duplicate ruleIds ({len(rule_ids)} rule(s))"))

    rule_id_set = set(rule_ids)
    sarif_results = run.get("results") or []

    # results ruleId references
    unknown_rule_ids = set()
    for r in sarif_results:
        rid = r.get("ruleId")
        if rid and rule_id_set and rid not in rule_id_set:
            unknown_rule_ids.add(rid)
    if unknown_rule_ids:
        results.append(check("fail", f"{prefix}: results reference unknown ruleIds: {', '.join(sorted(unknown_rule_ids))}"))
    else:
        results.append(check("pass", f"{prefix}: all result ruleIds reference known rules"))

    # locations
    missing_location = 0
    bad_uri = []
    for i, r in enumerate(sarif_results):
        locations = r.get("locations") or []
        if not locations:
            missing_location += 1
            continue
        for loc in locations:
            phys = loc.get("physicalLocation") or {}
            artifact = phys.get("artifactLocation") or {}
            uri = artifact.get("uri", "")
            if uri and ABSOLUTE_PATH_RE.match(uri):
                bad_uri.append(uri)
            region = phys.get("region") or {}
            if not region.get("startLine"):
                missing_location += 1

    if missing_location:
        results.append(check("warn", f"{prefix}: {missing_location} result(s) missing a valid location (URI + startLine)"))
    else:
        results.append(check("pass", f"{prefix}: all results have valid locations"))

    if bad_uri:
        sample = bad_uri[:3]
        results.append(check("warn", f"{prefix}: {len(bad_uri)} result(s) use absolute URIs that won't resolve in GitHub UI (e.g. {sample[0]})"))
    else:
        results.append(check("pass", f"{prefix}: URI patterns look sane"))

    # level values
    invalid_levels = set()
    for r in sarif_results:
        level = r.get("level")
        if level and level not in VALID_LEVELS:
            invalid_levels.add(level)
    if invalid_levels:
        results.append(check("fail", f"{prefix}: invalid level values: {', '.join(sorted(invalid_levels))}. Valid: {', '.join(sorted(VALID_LEVELS))}"))
    else:
        results.append(check("pass", f"{prefix}: all level values are valid"))

    return results, len(sarif_results), len(rule_id_set)


def format_status(status: str) -> str:
    return {"pass": "[PASS]", "fail": "[FAIL]", "warn": "[WARN]"}[status]


def main() -> None:
    sarif_file = os.environ.get("INPUT_SARIF_FILE", "").strip()
    strict = os.environ.get("INPUT_STRICT", "false").strip().lower() in ("true", "1", "yes")
    max_results_raw = os.environ.get("INPUT_MAX_RESULTS", "").strip()
    max_results = int(max_results_raw) if max_results_raw.isdigit() else None

    if not sarif_file:
        print("ERROR: 'sarif_file' input is required.", file=sys.stderr)
        sys.exit(2)
    if not os.path.exists(sarif_file):
        print(f"ERROR: File not found: {sarif_file}", file=sys.stderr)
        sys.exit(2)

    print(f"SARIF Validation: {sarif_file}")
    print("-" * 60)

    with open(sarif_file) as f:
        content = f.read()

    all_checks = []

    sarif, json_check = validate_json(content)
    all_checks.append(json_check)
    print(f"{format_status(json_check['status'])} {json_check['message']}")

    if sarif is None:
        sys.exit(1)

    for c in validate_top_level(sarif):
        all_checks.append(c)
        print(f"{format_status(c['status'])} {c['message']}")

    has_runs = isinstance(sarif.get("runs"), list) and len(sarif["runs"]) > 0
    total_results = 0
    total_rules = 0

    if has_runs:
        for i, run in enumerate(sarif["runs"]):
            run_checks, result_count, rule_count = validate_run(run, i)
            total_results += result_count
            total_rules += rule_count
            for c in run_checks:
                all_checks.append(c)
                print(f"{format_status(c['status'])} {c['message']}")

    if max_results is not None and total_results > max_results:
        c = check("warn", f"Result count {total_results} exceeds max_results threshold of {max_results}")
        all_checks.append(c)
        print(f"{format_status(c['status'])} {c['message']}")

    print("-" * 60)
    print(f"Summary: {total_results} result(s), {total_rules} unique rule(s)")

    has_failures = any(c["status"] == "fail" for c in all_checks)
    has_warnings = any(c["status"] == "warn" for c in all_checks)

    if has_failures:
        print(f"\nResult: FAIL ({sum(1 for c in all_checks if c['status'] == 'fail')} error(s))")
        sys.exit(1)
    if strict and has_warnings:
        print(f"\nResult: FAIL — strict mode ({sum(1 for c in all_checks if c['status'] == 'warn')} warning(s))")
        sys.exit(1)
    print("\nResult: PASS")
    sys.exit(0)


if __name__ == "__main__":
    main()
