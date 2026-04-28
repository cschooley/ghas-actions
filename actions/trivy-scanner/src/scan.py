#!/usr/bin/env python3
import os
import subprocess
import sys

VALID_SCAN_TYPES = {"image", "fs", "config"}
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]


def parse_bool(value: str) -> bool:
    return value.strip().lower() in ("true", "1", "yes")


def build_severity_flag(minimum: str) -> str:
    idx = SEVERITY_ORDER.index(minimum.upper())
    return ",".join(SEVERITY_ORDER[:idx + 1])


def build_trivy_cmd(
    scan_type: str,
    target: str,
    severity: str,
    output_file: str,
    ignore_unfixed: bool,
    trivy_config: str | None,
) -> list[str]:
    cmd = [
        "trivy", scan_type,
        "--format", "sarif",
        "--output", output_file,
        "--severity", build_severity_flag(severity),
    ]
    if ignore_unfixed:
        cmd.append("--ignore-unfixed")
    if trivy_config:
        cmd.extend(["--config", trivy_config])
    cmd.append(target)
    return cmd


def run_trivy(cmd: list[str]) -> int:
    return subprocess.run(cmd).returncode


def main() -> None:
    target = os.environ.get("INPUT_TARGET", "").strip()
    scan_type = os.environ.get("INPUT_SCAN_TYPE", "fs").strip().lower()
    severity = os.environ.get("INPUT_SEVERITY", "HIGH").strip().upper()
    output_file = os.environ.get("INPUT_OUTPUT_FILE", "trivy-results.sarif").strip()
    ignore_unfixed = parse_bool(os.environ.get("INPUT_IGNORE_UNFIXED", "false"))
    trivy_config = os.environ.get("INPUT_TRIVY_CONFIG", "").strip() or None

    if not target:
        print("ERROR: 'target' input is required.", file=sys.stderr)
        sys.exit(2)
    if scan_type not in VALID_SCAN_TYPES:
        print(
            f"ERROR: 'scan_type' must be one of: {', '.join(sorted(VALID_SCAN_TYPES))}. Got '{scan_type}'.",
            file=sys.stderr,
        )
        sys.exit(2)
    if severity not in SEVERITY_ORDER:
        print(
            f"ERROR: 'severity' must be one of: {', '.join(SEVERITY_ORDER)}. Got '{severity}'.",
            file=sys.stderr,
        )
        sys.exit(2)
    if trivy_config and not os.path.exists(trivy_config):
        print(f"ERROR: trivy_config file not found: {trivy_config}", file=sys.stderr)
        sys.exit(2)

    cmd = build_trivy_cmd(scan_type, target, severity, output_file, ignore_unfixed, trivy_config)

    print(f"Running Trivy {scan_type} scan: {target}")
    print(f"  severity: {build_severity_flag(severity)}")
    print(f"  output:   {output_file}")
    if ignore_unfixed:
        print("  ignore-unfixed: true")

    rc = run_trivy(cmd)
    if rc != 0:
        print(f"ERROR: Trivy exited with code {rc}", file=sys.stderr)
        sys.exit(rc)

    print(f"Scan complete. SARIF written to {output_file}")
    sys.exit(0)


if __name__ == "__main__":
    main()
