import importlib.util
import json
import os
import sys
from unittest.mock import patch

import pytest

_spec = importlib.util.spec_from_file_location(
    "zap_scan",
    os.path.join(os.path.dirname(__file__), "../../actions/zap-scanner/src/scan.py"),
)
scan = importlib.util.module_from_spec(_spec)
sys.modules["zap_scan"] = scan
_spec.loader.exec_module(scan)


BASE_ENV = {
    "INPUT_TARGET_URL": "http://localhost:8080",
    "INPUT_SCAN_TYPE": "baseline",
    "INPUT_OUTPUT_FILE": "zap-results.sarif",
    "INPUT_RULES_FILE": "",
    "INPUT_FAIL_ON_WARNINGS": "false",
}


def make_alert(plugin_id="10202", name="Test Alert", riskcode="2", instances=None):
    return {
        "pluginid": plugin_id,
        "alertRef": plugin_id,
        "alert": name,
        "name": name,
        "riskcode": riskcode,
        "confidence": "2",
        "riskdesc": "Medium (Medium)",
        "desc": "<p>Test <b>description</b></p>",
        "instances": instances or [
            {"uri": "http://localhost:8080/test", "method": "GET", "param": "q", "attack": "", "evidence": ""}
        ],
        "count": "1",
        "solution": "<p>Fix it</p>",
        "reference": "",
        "cweid": "79",
        "wascid": "8",
        "sourceid": "3",
    }


def make_zap_data(alerts=None):
    return {
        "@version": "D-2024-01-01",
        "@generated": "Mon, 1 Jan 2024 00:00:00",
        "site": [
            {
                "@name": "http://localhost:8080",
                "@host": "localhost",
                "@port": "8080",
                "@ssl": "false",
                "alerts": alerts if alerts is not None else [make_alert()],
            }
        ],
    }


# --- parse_bool ---

def test_parse_bool_true_values():
    for v in ("true", "True", "1", "yes"):
        assert scan.parse_bool(v) is True

def test_parse_bool_false_values():
    for v in ("false", "0", "no", ""):
        assert scan.parse_bool(v) is False


# --- strip_html ---

def test_strip_html_removes_tags():
    assert scan.strip_html("<p>Hello <b>world</b></p>") == "Hello world"

def test_strip_html_plain_text_unchanged():
    assert scan.strip_html("plain text") == "plain text"

def test_strip_html_empty():
    assert scan.strip_html("") == ""


# --- convert_to_sarif ---

def test_convert_produces_valid_sarif_structure():
    sarif = scan.convert_to_sarif(make_zap_data())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "ZAP"
    assert len(run["tool"]["driver"]["rules"]) == 1
    assert len(run["results"]) == 1

def test_convert_rule_id_from_pluginid():
    sarif = scan.convert_to_sarif(make_zap_data([make_alert(plugin_id="40012")]))
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "40012"

def test_convert_high_risk_maps_to_error():
    sarif = scan.convert_to_sarif(make_zap_data([make_alert(riskcode="3")]))
    assert sarif["runs"][0]["results"][0]["level"] == "error"

def test_convert_medium_risk_maps_to_warning():
    sarif = scan.convert_to_sarif(make_zap_data([make_alert(riskcode="2")]))
    assert sarif["runs"][0]["results"][0]["level"] == "warning"

def test_convert_low_risk_maps_to_note():
    sarif = scan.convert_to_sarif(make_zap_data([make_alert(riskcode="1")]))
    assert sarif["runs"][0]["results"][0]["level"] == "note"

def test_convert_info_risk_maps_to_note():
    sarif = scan.convert_to_sarif(make_zap_data([make_alert(riskcode="0")]))
    assert sarif["runs"][0]["results"][0]["level"] == "note"

def test_convert_security_severity_high():
    sarif = scan.convert_to_sarif(make_zap_data([make_alert(riskcode="3")]))
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.9"

def test_convert_security_severity_medium():
    sarif = scan.convert_to_sarif(make_zap_data([make_alert(riskcode="2")]))
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "5.0"

def test_convert_result_uri_from_instance():
    sarif = scan.convert_to_sarif(make_zap_data())
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "http://localhost:8080/test"

def test_convert_result_message_includes_method():
    sarif = scan.convert_to_sarif(make_zap_data())
    msg = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "GET" in msg

def test_convert_result_message_includes_param():
    sarif = scan.convert_to_sarif(make_zap_data())
    msg = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "q" in msg

def test_convert_multiple_instances_produce_multiple_results():
    instances = [
        {"uri": "http://localhost:8080/a", "method": "GET", "param": "", "attack": "", "evidence": ""},
        {"uri": "http://localhost:8080/b", "method": "POST", "param": "x", "attack": "", "evidence": ""},
    ]
    sarif = scan.convert_to_sarif(make_zap_data([make_alert(instances=instances)]))
    assert len(sarif["runs"][0]["results"]) == 2

def test_convert_deduplicates_rules_across_instances():
    instances = [
        {"uri": "http://localhost:8080/a", "method": "GET", "param": "", "attack": "", "evidence": ""},
        {"uri": "http://localhost:8080/b", "method": "GET", "param": "", "attack": "", "evidence": ""},
    ]
    sarif = scan.convert_to_sarif(make_zap_data([make_alert(plugin_id="10202", instances=instances)]))
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1

def test_convert_html_stripped_from_descriptions():
    sarif = scan.convert_to_sarif(make_zap_data())
    desc = sarif["runs"][0]["tool"]["driver"]["rules"][0]["fullDescription"]["text"]
    assert "<" not in desc
    assert "description" in desc

def test_convert_empty_site_produces_no_results():
    sarif = scan.convert_to_sarif(make_zap_data(alerts=[]))
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

def test_convert_version_from_zap_data():
    data = make_zap_data()
    data["@version"] = "D-2024-06-01"
    sarif = scan.convert_to_sarif(data)
    assert sarif["runs"][0]["tool"]["driver"]["version"] == "D-2024-06-01"


# --- build_zap_cmd ---

def test_build_cmd_baseline_uses_baseline_script():
    cmd = scan.build_zap_cmd("baseline", "http://target", "/tmp/work")
    assert "zap-baseline.py" in cmd

def test_build_cmd_full_uses_full_scan_script():
    cmd = scan.build_zap_cmd("full", "http://target", "/tmp/work")
    assert "zap-full-scan.py" in cmd

def test_build_cmd_target_url_present():
    cmd = scan.build_zap_cmd("baseline", "http://target:8080", "/tmp/work")
    assert "http://target:8080" in cmd

def test_build_cmd_json_output_flag():
    cmd = scan.build_zap_cmd("baseline", "http://target", "/tmp/work")
    assert "-J" in cmd
    assert "zap-report.json" in cmd

def test_build_cmd_volume_mount_present():
    cmd = scan.build_zap_cmd("baseline", "http://target", "/my/work/dir")
    assert any("/my/work/dir:/zap/wrk:rw" in arg for arg in cmd)

def test_build_cmd_host_gateway_present():
    cmd = scan.build_zap_cmd("baseline", "http://target", "/tmp/work")
    assert "--add-host=host.docker.internal:host-gateway" in cmd

def test_build_cmd_rules_flag_when_use_rules_true():
    cmd = scan.build_zap_cmd("baseline", "http://target", "/tmp/work", use_rules=True)
    assert "-c" in cmd
    assert "rules.tsv" in cmd

def test_build_cmd_no_rules_flag_by_default():
    cmd = scan.build_zap_cmd("baseline", "http://target", "/tmp/work")
    assert "-c" not in cmd


# --- main: input validation ---

def test_main_missing_target_url(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_TARGET_URL": ""}, clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "target_url" in capsys.readouterr().err

def test_main_invalid_scan_type(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SCAN_TYPE": "deep"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2

def test_main_missing_rules_file(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_RULES_FILE": "/nonexistent/rules.tsv"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "not found" in capsys.readouterr().err


# --- main: execution paths ---

def _run_main_with_zap_data(env, zap_data, zap_rc=0, tmp_path=None):
    """Helper: patches run_zap to write fixture JSON and return zap_rc."""
    import tempfile as _tempfile

    orig_mkdtemp = _tempfile.mkdtemp

    def fake_mkdtemp(**kwargs):
        d = orig_mkdtemp(**kwargs)
        with open(os.path.join(d, "zap-report.json"), "w") as f:
            json.dump(zap_data, f)
        return d

    with patch.dict(os.environ, env, clear=True):
        with patch("zap_scan.run_zap", return_value=zap_rc):
            with patch("zap_scan.tempfile.mkdtemp", side_effect=fake_mkdtemp):
                with pytest.raises(SystemExit) as exc:
                    scan.main()
    return exc.value.code


def test_main_happy_path_exits_0(tmp_path, capsys):
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(tmp_path / "out.sarif")}
    rc = _run_main_with_zap_data(env, make_zap_data())
    assert rc == 0
    assert "Scan complete" in capsys.readouterr().out

def test_main_writes_valid_sarif(tmp_path):
    out = tmp_path / "out.sarif"
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(out)}
    _run_main_with_zap_data(env, make_zap_data())
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1

def test_main_zap_rc1_exits_0_when_fail_on_warnings_false(tmp_path):
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(tmp_path / "out.sarif"), "INPUT_FAIL_ON_WARNINGS": "false"}
    rc = _run_main_with_zap_data(env, make_zap_data(), zap_rc=1)
    assert rc == 0

def test_main_zap_rc2_exits_0_when_fail_on_warnings_false(tmp_path):
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(tmp_path / "out.sarif"), "INPUT_FAIL_ON_WARNINGS": "false"}
    rc = _run_main_with_zap_data(env, make_zap_data(), zap_rc=2)
    assert rc == 0

def test_main_zap_rc1_exits_1_when_fail_on_warnings_true(tmp_path):
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(tmp_path / "out.sarif"), "INPUT_FAIL_ON_WARNINGS": "true"}
    rc = _run_main_with_zap_data(env, make_zap_data(), zap_rc=1)
    assert rc == 1

def test_main_zap_rc2_exits_1_when_fail_on_warnings_true(tmp_path):
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(tmp_path / "out.sarif"), "INPUT_FAIL_ON_WARNINGS": "true"}
    rc = _run_main_with_zap_data(env, make_zap_data(), zap_rc=2)
    assert rc == 1

def test_main_zap_rc3_always_exits_1(tmp_path):
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(tmp_path / "out.sarif"), "INPUT_FAIL_ON_WARNINGS": "false"}
    rc = _run_main_with_zap_data(env, make_zap_data(), zap_rc=3)
    assert rc == 1

def test_main_zap_rc4_exits_1_with_error(tmp_path, capsys):
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(tmp_path / "out.sarif")}
    with patch.dict(os.environ, env, clear=True):
        with patch("zap_scan.run_zap", return_value=4):
            with pytest.raises(SystemExit) as exc:
                scan.main()
    assert exc.value.code == 1
    assert "internal error" in capsys.readouterr().err

def test_main_full_scan_prints_warning(tmp_path, capsys):
    env = {**BASE_ENV, "INPUT_SCAN_TYPE": "full", "INPUT_OUTPUT_FILE": str(tmp_path / "out.sarif")}
    _run_main_with_zap_data(env, make_zap_data())
    assert "active attack" in capsys.readouterr().err
