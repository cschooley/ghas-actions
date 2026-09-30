import importlib.util
import json
import os
import sys
from unittest.mock import patch

import pytest

_spec = importlib.util.spec_from_file_location(
    "stackhawk_scan",
    os.path.join(os.path.dirname(__file__), "../../actions/stackhawk-scanner/src/scan.py"),
)
scan = importlib.util.module_from_spec(_spec)
sys.modules["stackhawk_scan"] = scan
_spec.loader.exec_module(scan)


BASE_ENV = {
    "INPUT_API_KEY": "hawk.test.key",
    "INPUT_APP_ID": "00000000-0000-0000-0000-000000000000",
    "INPUT_HAWK_CONFIG": "stackhawk.yml",
    "INPUT_OUTPUT_FILE": "stackhawk-results.sarif",
    "INPUT_FAIL_ON_FINDINGS": "true",
}


def make_result(rule_id="40012", locations=True):
    result = {
        "ruleId": rule_id,
        "level": "error",
        "message": {"text": "Cross Site Scripting (Reflected)"},
    }
    if locations:
        result["locations"] = [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": "http://localhost:8080/search"},
                    "region": {"startLine": 1},
                }
            }
        ]
    return result


def make_sarif(results=None):
    return {
        "version": "2.1.0",
        "runs": [
            {
                "tool": {"driver": {"name": "HawkScan", "rules": [{"id": "40012"}]}},
                "results": results if results is not None else [make_result()],
            }
        ],
    }


@pytest.fixture
def workspace(tmp_path):
    (tmp_path / "stackhawk.yml").write_text("app:\n  applicationId: ${APP_ID}\n")
    return tmp_path


def _env(workspace, **overrides):
    return {
        **BASE_ENV,
        "GITHUB_WORKSPACE": str(workspace),
        "INPUT_OUTPUT_FILE": str(workspace / "out.sarif"),
        **overrides,
    }


def _run_main(env, sarif=None, hawk_rc=0):
    """Patches run_hawk to write fixture SARIF into the workspace and return hawk_rc."""
    calls = {}

    def fake_run_hawk(cmd, run_env):
        calls["cmd"] = cmd
        calls["env"] = run_env
        if sarif is not None:
            with open(os.path.join(env["GITHUB_WORKSPACE"], "stackhawk.sarif"), "w") as f:
                json.dump(sarif, f)
        return hawk_rc

    with patch.dict(os.environ, env, clear=True):
        with patch("stackhawk_scan.run_hawk", side_effect=fake_run_hawk):
            with pytest.raises(SystemExit) as exc:
                scan.main()
    return exc.value.code, calls


# --- parse_bool ---

def test_parse_bool_true_values():
    for v in ("true", "True", "1", "yes"):
        assert scan.parse_bool(v) is True

def test_parse_bool_false_values():
    for v in ("false", "0", "no", ""):
        assert scan.parse_bool(v) is False


# --- resolve_config_path ---

def test_resolve_config_path_relative(tmp_path):
    assert scan.resolve_config_path("stackhawk.yml", str(tmp_path)) == "stackhawk.yml"

def test_resolve_config_path_nested(tmp_path):
    assert scan.resolve_config_path("config/hawk.yml", str(tmp_path)) == os.path.join("config", "hawk.yml")

def test_resolve_config_path_rejects_traversal(tmp_path):
    assert scan.resolve_config_path("../outside.yml", str(tmp_path)) is None

def test_resolve_config_path_rejects_absolute_outside(tmp_path):
    assert scan.resolve_config_path("/etc/passwd", str(tmp_path)) is None


# --- build_hawk_cmd ---

def test_build_cmd_uses_hawkscan_image():
    cmd = scan.build_hawk_cmd("/ws", "stackhawk.yml")
    assert scan.HAWKSCAN_IMAGE in cmd

def test_build_cmd_mounts_workspace_at_hawk():
    cmd = scan.build_hawk_cmd("/my/ws", "stackhawk.yml")
    assert "/my/ws:/hawk:rw" in cmd

def test_build_cmd_enables_sarif_artifact():
    cmd = scan.build_hawk_cmd("/ws", "stackhawk.yml")
    assert "SARIF_ARTIFACT=true" in cmd

def test_build_cmd_passes_secrets_by_name_only():
    cmd = scan.build_hawk_cmd("/ws", "stackhawk.yml")
    assert "API_KEY" in cmd
    assert "APP_ID" in cmd
    assert not any(arg.startswith("API_KEY=") for arg in cmd)

def test_build_cmd_config_is_last_arg():
    cmd = scan.build_hawk_cmd("/ws", "config/hawk.yml")
    assert cmd[-1] == "config/hawk.yml"

def test_build_cmd_uses_host_network():
    cmd = scan.build_hawk_cmd("/ws", "stackhawk.yml")
    assert "--network" in cmd
    assert "host" in cmd


# --- normalize_sarif / count_results ---

def test_normalize_backfills_missing_locations():
    sarif = scan.normalize_sarif(make_sarif([make_result(locations=False)]), fallback_uri="stackhawk.yml")
    loc = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "stackhawk.yml"
    assert loc["region"]["startLine"] == 1

def test_normalize_keeps_existing_locations():
    sarif = scan.normalize_sarif(make_sarif(), fallback_uri="stackhawk.yml")
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "http://localhost:8080/search"

def test_normalize_sets_version_and_schema():
    data = make_sarif()
    del data["version"]
    sarif = scan.normalize_sarif(data, fallback_uri="x")
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif

def test_count_results_across_runs():
    data = make_sarif([make_result(), make_result()])
    data["runs"].append({"tool": {"driver": {"name": "HawkScan"}}, "results": [make_result()]})
    assert scan.count_results(data) == 3

def test_count_results_empty():
    assert scan.count_results(make_sarif([])) == 0


# --- main: input validation ---

def test_main_missing_api_key(workspace, capsys):
    with patch.dict(os.environ, _env(workspace, INPUT_API_KEY=""), clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "api_key" in capsys.readouterr().err

def test_main_missing_app_id(workspace, capsys):
    with patch.dict(os.environ, _env(workspace, INPUT_APP_ID=""), clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "app_id" in capsys.readouterr().err

def test_main_missing_config(workspace, capsys):
    with patch.dict(os.environ, _env(workspace, INPUT_HAWK_CONFIG="nope.yml"), clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "not found" in capsys.readouterr().err

def test_main_config_outside_workspace(workspace, capsys):
    with patch.dict(os.environ, _env(workspace, INPUT_HAWK_CONFIG="../stackhawk.yml"), clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "inside the workspace" in capsys.readouterr().err


# --- main: execution paths ---

def test_main_clean_scan_exits_0(workspace, capsys):
    rc, _ = _run_main(_env(workspace), sarif=make_sarif([]))
    assert rc == 0
    assert "0 finding(s)" in capsys.readouterr().out

def test_main_writes_normalized_sarif(workspace):
    _run_main(_env(workspace, INPUT_FAIL_ON_FINDINGS="false"), sarif=make_sarif([make_result(locations=False)]))
    sarif = json.loads((workspace / "out.sarif").read_text())
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"][0]["locations"]

def test_main_passes_secrets_via_env(workspace):
    _, calls = _run_main(_env(workspace), sarif=make_sarif([]))
    assert calls["env"]["API_KEY"] == BASE_ENV["INPUT_API_KEY"]
    assert calls["env"]["APP_ID"] == BASE_ENV["INPUT_APP_ID"]
    assert BASE_ENV["INPUT_API_KEY"] not in calls["cmd"]

def test_main_findings_exit_1_when_fail_on_findings_true(workspace, capsys):
    rc, _ = _run_main(_env(workspace), sarif=make_sarif())
    assert rc == 1
    assert "FAILED" in capsys.readouterr().err

def test_main_findings_exit_0_in_advisory_mode(workspace, capsys):
    rc, _ = _run_main(_env(workspace, INPUT_FAIL_ON_FINDINGS="false"), sarif=make_sarif())
    assert rc == 0
    assert "Advisory mode" in capsys.readouterr().out

def test_main_threshold_exit_42_fails_even_with_empty_sarif(workspace):
    rc, _ = _run_main(_env(workspace), sarif=make_sarif([]), hawk_rc=42)
    assert rc == 1

def test_main_threshold_exit_42_advisory_exits_0(workspace):
    rc, _ = _run_main(_env(workspace, INPUT_FAIL_ON_FINDINGS="false"), sarif=make_sarif(), hawk_rc=42)
    assert rc == 0

def test_main_scanner_error_exits_1(workspace, capsys):
    rc, _ = _run_main(_env(workspace), sarif=None, hawk_rc=1)
    assert rc == 1
    assert "exited with code 1" in capsys.readouterr().err

def test_main_scanner_error_fails_even_in_advisory_mode(workspace):
    rc, _ = _run_main(_env(workspace, INPUT_FAIL_ON_FINDINGS="false"), sarif=None, hawk_rc=2)
    assert rc == 1

def test_main_missing_sarif_exits_1(workspace, capsys):
    rc, _ = _run_main(_env(workspace), sarif=None, hawk_rc=0)
    assert rc == 1
    assert "did not produce" in capsys.readouterr().err

def test_main_removes_stale_sarif_before_scan(workspace):
    (workspace / "stackhawk.sarif").write_text(json.dumps(make_sarif()))
    rc, _ = _run_main(_env(workspace), sarif=None, hawk_rc=0)
    assert rc == 1
    assert not (workspace / "stackhawk.sarif").exists()
