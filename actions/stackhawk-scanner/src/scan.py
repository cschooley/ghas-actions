#!/usr/bin/env python3
import json
import os
import subprocess
import sys

HAWKSCAN_IMAGE = "stackhawk/hawkscan:latest"
NATIVE_SARIF_NAME = "stackhawk.sarif"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# HawkScan exits 42 when findings meet or exceed hawk.failureThreshold.
# Any other non-zero code is a scanner or configuration error.
EXIT_THRESHOLD_MET = 42


def parse_bool(value: str) -> bool:
    return value.strip().lower() in ("true", "1", "yes")


def resolve_config_path(hawk_config: str, workspace: str) -> str | None:
    """Return hawk_config relative to workspace, or None if it escapes the workspace."""
    workspace = os.path.realpath(workspace)
    config_abs = os.path.realpath(os.path.join(workspace, hawk_config))
    if os.path.commonpath([workspace, config_abs]) != workspace:
        return None
    return os.path.relpath(config_abs, workspace)


def build_hawk_cmd(workspace: str, config_rel: str) -> list[str]:
    # API_KEY is passed by name only so the secret never appears in the process list;
    # docker copies its value from the environment of this process.
    return [
        "docker", "run", "--rm",
        "--network", "host",
        "-v", f"{workspace}:/hawk:rw",
        "-e", "API_KEY",
        "-e", "APP_ID",
        "-e", "SARIF_ARTIFACT=true",
        HAWKSCAN_IMAGE,
        config_rel,
    ]


def run_hawk(cmd: list[str], env: dict) -> int:
    return subprocess.run(cmd, env=env).returncode


def normalize_sarif(sarif: dict, fallback_uri: str) -> dict:
    """Make native HawkScan SARIF acceptable to GitHub code scanning.

    GitHub rejects results without a location, and DAST findings do not always carry one.
    """
    sarif["version"] = "2.1.0"
    sarif.setdefault("$schema", SARIF_SCHEMA)
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            if not result.get("locations"):
                result["locations"] = [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": fallback_uri},
                            "region": {"startLine": 1},
                        }
                    }
                ]
    return sarif


def count_results(sarif: dict) -> int:
    return sum(len(run.get("results", [])) for run in sarif.get("runs", []))


def main() -> None:
    api_key = os.environ.get("INPUT_API_KEY", "").strip()
    app_id = os.environ.get("INPUT_APP_ID", "").strip()
    hawk_config = os.environ.get("INPUT_HAWK_CONFIG", "stackhawk.yml").strip() or "stackhawk.yml"
    output_file = os.environ.get("INPUT_OUTPUT_FILE", "stackhawk-results.sarif").strip()
    fail_on_findings = parse_bool(os.environ.get("INPUT_FAIL_ON_FINDINGS", "true"))
    workspace = os.environ.get("GITHUB_WORKSPACE", os.getcwd())

    if not api_key:
        print("ERROR: 'api_key' input is required. Pass it from a secret.", file=sys.stderr)
        sys.exit(2)
    if not app_id:
        print("ERROR: 'app_id' input is required.", file=sys.stderr)
        sys.exit(2)

    config_rel = resolve_config_path(hawk_config, workspace)
    if config_rel is None:
        print(f"ERROR: hawk_config must be inside the workspace: {hawk_config}", file=sys.stderr)
        sys.exit(2)
    if not os.path.isfile(os.path.join(workspace, config_rel)):
        print(f"ERROR: hawk_config not found: {hawk_config}", file=sys.stderr)
        sys.exit(2)

    native_sarif = os.path.join(workspace, NATIVE_SARIF_NAME)
    if os.path.exists(native_sarif):
        # Remove stale output so a failed scan can't be mistaken for a fresh result.
        os.remove(native_sarif)

    env = {**os.environ, "API_KEY": api_key, "APP_ID": app_id}
    cmd = build_hawk_cmd(workspace, config_rel)
    print(f"Running HawkScan with config: {config_rel}")
    rc = run_hawk(cmd, env)

    if rc not in (0, EXIT_THRESHOLD_MET):
        print(f"ERROR: HawkScan exited with code {rc}. Check the scan log above.", file=sys.stderr)
        sys.exit(1)

    if not os.path.exists(native_sarif):
        print(
            f"ERROR: HawkScan did not produce {NATIVE_SARIF_NAME}. "
            "Check that the target is reachable and Docker is available.",
            file=sys.stderr,
        )
        sys.exit(1)

    with open(native_sarif) as f:
        sarif = json.load(f)

    sarif = normalize_sarif(sarif, fallback_uri=config_rel)
    finding_count = count_results(sarif)
    print(f"Scan complete — {finding_count} finding(s). Writing SARIF to {output_file}")

    with open(output_file, "w") as f:
        json.dump(sarif, f, indent=2)

    has_findings = rc == EXIT_THRESHOLD_MET or finding_count > 0
    if has_findings and fail_on_findings:
        print("FAILED: HawkScan reported findings and fail_on_findings is true.", file=sys.stderr)
        sys.exit(1)
    if has_findings:
        print("Advisory mode: findings reported but not failing the build.")

    sys.exit(0)


if __name__ == "__main__":
    main()
