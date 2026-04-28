import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../actions/trivy-scanner/src"))
import scan


BASE_ENV = {
    "INPUT_TARGET": ".",
    "INPUT_SCAN_TYPE": "fs",
    "INPUT_SEVERITY": "HIGH",
    "INPUT_OUTPUT_FILE": "trivy-results.sarif",
    "INPUT_IGNORE_UNFIXED": "false",
    "INPUT_TRIVY_CONFIG": "",
}


# --- parse_bool ---

def test_parse_bool_true_values():
    for v in ("true", "True", "TRUE", "1", "yes"):
        assert scan.parse_bool(v) is True

def test_parse_bool_false_values():
    for v in ("false", "False", "0", "no", ""):
        assert scan.parse_bool(v) is False


# --- build_severity_flag ---

def test_severity_critical_only():
    assert scan.build_severity_flag("CRITICAL") == "CRITICAL"

def test_severity_high_includes_critical():
    assert scan.build_severity_flag("HIGH") == "CRITICAL,HIGH"

def test_severity_medium_includes_above():
    assert scan.build_severity_flag("MEDIUM") == "CRITICAL,HIGH,MEDIUM"

def test_severity_low_all():
    assert scan.build_severity_flag("LOW") == "CRITICAL,HIGH,MEDIUM,LOW"


# --- build_trivy_cmd ---

def test_build_cmd_fs_basic():
    cmd = scan.build_trivy_cmd("fs", ".", "HIGH", "out.sarif", False, None)
    assert cmd == ["trivy", "fs", "--format", "sarif", "--output", "out.sarif", "--severity", "CRITICAL,HIGH", "."]

def test_build_cmd_image_type():
    cmd = scan.build_trivy_cmd("image", "python:3.11-slim", "CRITICAL", "out.sarif", False, None)
    assert cmd[1] == "image"
    assert cmd[-1] == "python:3.11-slim"

def test_build_cmd_config_type():
    cmd = scan.build_trivy_cmd("config", ".", "HIGH", "out.sarif", False, None)
    assert cmd[1] == "config"

def test_build_cmd_ignore_unfixed_present():
    cmd = scan.build_trivy_cmd("fs", ".", "HIGH", "out.sarif", True, None)
    assert "--ignore-unfixed" in cmd

def test_build_cmd_ignore_unfixed_absent():
    cmd = scan.build_trivy_cmd("fs", ".", "HIGH", "out.sarif", False, None)
    assert "--ignore-unfixed" not in cmd

def test_build_cmd_with_config():
    cmd = scan.build_trivy_cmd("fs", ".", "HIGH", "out.sarif", False, "trivy.yaml")
    assert "--config" in cmd
    config_idx = cmd.index("--config")
    assert cmd[config_idx + 1] == "trivy.yaml"

def test_build_cmd_without_config():
    cmd = scan.build_trivy_cmd("fs", ".", "HIGH", "out.sarif", False, None)
    assert "--config" not in cmd

def test_build_cmd_target_is_last():
    cmd = scan.build_trivy_cmd("fs", "/some/path", "HIGH", "out.sarif", False, None)
    assert cmd[-1] == "/some/path"

def test_build_cmd_sarif_format():
    cmd = scan.build_trivy_cmd("fs", ".", "HIGH", "out.sarif", False, None)
    fmt_idx = cmd.index("--format")
    assert cmd[fmt_idx + 1] == "sarif"


# --- main: input validation ---

def test_main_missing_target(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_TARGET": ""}, clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "target" in capsys.readouterr().err

def test_main_invalid_scan_type(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SCAN_TYPE": "repo"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2

def test_main_invalid_severity(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SEVERITY": "EXTREME"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2

def test_main_missing_config_file(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_TRIVY_CONFIG": "/nonexistent/trivy.yaml"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "not found" in capsys.readouterr().err

def test_main_valid_config_file(tmp_path, capsys):
    config = tmp_path / "trivy.yaml"
    config.write_text("timeout: 5m\n")
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_TRIVY_CONFIG": str(config)}, clear=True):
        with patch("scan.run_trivy", return_value=0):
            with pytest.raises(SystemExit) as exc:
                scan.main()
    assert exc.value.code == 0


# --- main: execution ---

def test_main_happy_path_exits_0(capsys):
    with patch.dict(os.environ, BASE_ENV, clear=True):
        with patch("scan.run_trivy", return_value=0):
            with pytest.raises(SystemExit) as exc:
                scan.main()
    assert exc.value.code == 0
    assert "Scan complete" in capsys.readouterr().out

def test_main_trivy_failure_propagates(capsys):
    with patch.dict(os.environ, BASE_ENV, clear=True):
        with patch("scan.run_trivy", return_value=2):
            with pytest.raises(SystemExit) as exc:
                scan.main()
    assert exc.value.code == 2
    assert "ERROR" in capsys.readouterr().err

def test_main_passes_correct_cmd_to_run_trivy():
    captured = []
    def fake_run(cmd):
        captured.extend(cmd)
        return 0
    with patch.dict(os.environ, BASE_ENV, clear=True):
        with patch("scan.run_trivy", side_effect=fake_run):
            with pytest.raises(SystemExit):
                scan.main()
    assert "fs" in captured
    assert "--format" in captured
    assert "sarif" in captured
    assert "CRITICAL,HIGH" in captured

def test_main_ignore_unfixed_passed_through():
    captured = []
    def fake_run(cmd):
        captured.extend(cmd)
        return 0
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_IGNORE_UNFIXED": "true"}, clear=True):
        with patch("scan.run_trivy", side_effect=fake_run):
            with pytest.raises(SystemExit):
                scan.main()
    assert "--ignore-unfixed" in captured

def test_main_severity_low_passes_all_levels():
    captured = []
    def fake_run(cmd):
        captured.extend(cmd)
        return 0
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SEVERITY": "LOW"}, clear=True):
        with patch("scan.run_trivy", side_effect=fake_run):
            with pytest.raises(SystemExit):
                scan.main()
    sev_idx = captured.index("--severity")
    assert captured[sev_idx + 1] == "CRITICAL,HIGH,MEDIUM,LOW"

def test_main_image_scan_type():
    captured = []
    def fake_run(cmd):
        captured.extend(cmd)
        return 0
    env = {**BASE_ENV, "INPUT_SCAN_TYPE": "image", "INPUT_TARGET": "python:3.11-slim"}
    with patch.dict(os.environ, env, clear=True):
        with patch("scan.run_trivy", side_effect=fake_run):
            with pytest.raises(SystemExit):
                scan.main()
    assert "image" in captured
    assert "python:3.11-slim" in captured
