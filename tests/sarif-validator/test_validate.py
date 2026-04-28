import json
import os
import sys
from unittest.mock import patch

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../actions/sarif-validator/src"))
import validate


def make_sarif(
    version="2.1.0",
    runs=None,
    include_version=True,
    include_runs=True,
) -> dict:
    sarif = {}
    if include_version:
        sarif["version"] = version
    if include_runs:
        sarif["runs"] = runs if runs is not None else [make_run()]
    return sarif


def make_run(
    driver_name="TestTool",
    rules=None,
    results=None,
) -> dict:
    if rules is None:
        rules = [{"id": "rule-1", "name": "Rule One"}]
    if results is None:
        results = [make_result()]
    return {
        "tool": {"driver": {"name": driver_name, "rules": rules}},
        "results": results,
    }


def make_result(
    rule_id="rule-1",
    level="warning",
    uri="src/app.py",
    start_line=10,
) -> dict:
    result: dict = {}
    if rule_id:
        result["ruleId"] = rule_id
    if level:
        result["level"] = level
    result["locations"] = [
        {
            "physicalLocation": {
                "artifactLocation": {"uri": uri},
                "region": {"startLine": start_line},
            }
        }
    ]
    return result


def write_sarif(tmp_path, data: dict) -> str:
    path = tmp_path / "test.sarif"
    path.write_text(json.dumps(data))
    return str(path)


# --- validate_json ---

def test_validate_json_valid():
    sarif, c = validate.validate_json('{"version": "2.1.0"}')
    assert c["status"] == "pass"
    assert sarif == {"version": "2.1.0"}

def test_validate_json_invalid():
    sarif, c = validate.validate_json("{not valid json")
    assert c["status"] == "fail"
    assert sarif is None


# --- validate_top_level ---

def test_top_level_valid():
    checks = validate.validate_top_level(make_sarif())
    assert all(c["status"] == "pass" for c in checks)

def test_top_level_missing_version():
    checks = validate.validate_top_level(make_sarif(include_version=False))
    statuses = [c["status"] for c in checks]
    assert "fail" in statuses

def test_top_level_unsupported_version():
    checks = validate.validate_top_level(make_sarif(version="1.0.0"))
    assert any(c["status"] == "fail" and "Unsupported" in c["message"] for c in checks)

def test_top_level_missing_runs():
    checks = validate.validate_top_level(make_sarif(include_runs=False))
    assert any(c["status"] == "fail" and "runs" in c["message"] for c in checks)

def test_top_level_empty_runs():
    checks = validate.validate_top_level(make_sarif(runs=[]))
    assert any(c["status"] == "fail" for c in checks)


# --- validate_run ---

def test_run_valid():
    checks, result_count, rule_count = validate.validate_run(make_run(), 0)
    assert all(c["status"] == "pass" for c in checks)
    assert result_count == 1
    assert rule_count == 1

def test_run_missing_driver_name():
    run = make_run(driver_name=None)
    del run["tool"]["driver"]["name"]
    checks, _, _ = validate.validate_run(run, 0)
    assert any(c["status"] == "fail" and "driver.name" in c["message"] for c in checks)

def test_run_duplicate_rule_ids():
    rules = [{"id": "rule-1"}, {"id": "rule-1"}]
    run = make_run(rules=rules, results=[])
    checks, _, _ = validate.validate_run(run, 0)
    assert any(c["status"] == "fail" and "duplicate" in c["message"] for c in checks)

def test_run_unknown_rule_id():
    results = [make_result(rule_id="unknown-rule")]
    run = make_run(rules=[{"id": "rule-1"}], results=results)
    checks, _, _ = validate.validate_run(run, 0)
    assert any(c["status"] == "fail" and "unknown ruleIds" in c["message"] for c in checks)

def test_run_result_with_no_rules_defined_passes():
    run = make_run(rules=[], results=[make_result(rule_id="any-rule")])
    checks, _, _ = validate.validate_run(run, 0)
    assert not any(c["status"] == "fail" and "unknown ruleIds" in c["message"] for c in checks)

def test_run_invalid_level():
    results = [make_result(level="critical")]
    run = make_run(results=results)
    checks, _, _ = validate.validate_run(run, 0)
    assert any(c["status"] == "fail" and "invalid level" in c["message"] for c in checks)

def test_run_all_valid_levels():
    for level in ("error", "warning", "note", "none"):
        results = [make_result(level=level)]
        run = make_run(results=results)
        checks, _, _ = validate.validate_run(run, 0)
        assert not any(c["status"] == "fail" and "invalid level" in c["message"] for c in checks)

def test_run_absolute_unix_uri():
    results = [make_result(uri="/home/runner/work/repo/src/app.py")]
    run = make_run(results=results)
    checks, _, _ = validate.validate_run(run, 0)
    assert any(c["status"] == "warn" and "absolute" in c["message"] for c in checks)

def test_run_absolute_windows_uri():
    results = [make_result(uri="C:\\Users\\runner\\src\\app.py")]
    run = make_run(results=results)
    checks, _, _ = validate.validate_run(run, 0)
    assert any(c["status"] == "warn" and "absolute" in c["message"] for c in checks)

def test_run_relative_uri_passes():
    results = [make_result(uri="src/app.py")]
    run = make_run(results=results)
    checks, _, _ = validate.validate_run(run, 0)
    assert not any("absolute" in c["message"] for c in checks)

def test_run_missing_start_line():
    result = make_result()
    result["locations"][0]["physicalLocation"]["region"] = {}
    run = make_run(results=[result])
    checks, _, _ = validate.validate_run(run, 0)
    assert any(c["status"] == "warn" and "missing a valid location" in c["message"] for c in checks)

def test_run_no_locations():
    result = make_result()
    result["locations"] = []
    run = make_run(results=[result])
    checks, _, _ = validate.validate_run(run, 0)
    assert any(c["status"] == "warn" and "missing a valid location" in c["message"] for c in checks)

def test_run_counts():
    rules = [{"id": "r1"}, {"id": "r2"}]
    results = [make_result("r1"), make_result("r2"), make_result("r1")]
    _, result_count, rule_count = validate.validate_run(make_run(rules=rules, results=results), 0)
    assert result_count == 3
    assert rule_count == 2


# --- main: input validation ---

def test_main_missing_sarif_file_exits_2():
    with patch.dict(os.environ, {}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 2

def test_main_file_not_found_exits_2():
    with patch.dict(os.environ, {"INPUT_SARIF_FILE": "/nonexistent/file.sarif"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 2


# --- main: end-to-end ---

BASE_ENV = {"INPUT_STRICT": "false", "INPUT_MAX_RESULTS": "", "INPUT_FAIL_ON_FINDINGS": "true"}


def test_main_valid_sarif_exits_0(tmp_path):
    path = write_sarif(tmp_path, make_sarif())
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SARIF_FILE": path}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 0

def test_main_invalid_json_exits_1(tmp_path):
    path = tmp_path / "bad.sarif"
    path.write_text("{not json")
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SARIF_FILE": str(path)}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 1

def test_main_wrong_version_exits_1(tmp_path):
    path = write_sarif(tmp_path, make_sarif(version="1.0.0"))
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SARIF_FILE": path}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 1

def test_main_warnings_pass_non_strict(tmp_path):
    results = [make_result(uri="/absolute/path.py")]
    path = write_sarif(tmp_path, make_sarif(runs=[make_run(results=results)]))
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SARIF_FILE": path}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 0

def test_main_warnings_fail_strict(tmp_path):
    results = [make_result(uri="/absolute/path.py")]
    path = write_sarif(tmp_path, make_sarif(runs=[make_run(results=results)]))
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SARIF_FILE": path, "INPUT_STRICT": "true"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 1

def test_main_max_results_exceeded_warns(tmp_path, capsys):
    results = [make_result() for _ in range(5)]
    path = write_sarif(tmp_path, make_sarif(runs=[make_run(results=results)]))
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SARIF_FILE": path, "INPUT_MAX_RESULTS": "3"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 0
    assert "exceeds max_results" in capsys.readouterr().out

def test_main_max_results_exceeded_fails_strict(tmp_path):
    results = [make_result() for _ in range(5)]
    path = write_sarif(tmp_path, make_sarif(runs=[make_run(results=results)]))
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SARIF_FILE": path, "INPUT_STRICT": "true", "INPUT_MAX_RESULTS": "3"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 1


# --- advisory mode ---

def test_main_advisory_mode_exits_0_on_fail(tmp_path):
    path = write_sarif(tmp_path, make_sarif(version="1.0.0"))
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SARIF_FILE": path, "INPUT_FAIL_ON_FINDINGS": "false"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 0

def test_main_advisory_mode_exits_0_on_strict_warn(tmp_path):
    results = [make_result(uri="/absolute/path.py")]
    path = write_sarif(tmp_path, make_sarif(runs=[make_run(results=results)]))
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SARIF_FILE": path, "INPUT_STRICT": "true", "INPUT_FAIL_ON_FINDINGS": "false"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            validate.main()
    assert exc.value.code == 0

def test_main_advisory_mode_prints_advisory_note(tmp_path, capsys):
    path = write_sarif(tmp_path, make_sarif(version="1.0.0"))
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SARIF_FILE": path, "INPUT_FAIL_ON_FINDINGS": "false"}, clear=True):
        with pytest.raises(SystemExit):
            validate.main()
    assert "Advisory mode" in capsys.readouterr().out
