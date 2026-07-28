import importlib.util
import json
import os
import sys
from unittest.mock import patch

import pytest

_spec = importlib.util.spec_from_file_location(
    "sonar_scan",
    os.path.join(os.path.dirname(__file__), "../../actions/sonarqube-scanner/src/scan.py"),
)
scan = importlib.util.module_from_spec(_spec)
sys.modules["sonar_scan"] = scan
_spec.loader.exec_module(scan)


BASE_ENV = {
    "INPUT_SONAR_HOST_URL": "https://sonarcloud.io",
    "INPUT_SONAR_TOKEN": "test-token",
    "INPUT_PROJECT_KEY": "my-project",
    "INPUT_ORGANIZATION": "my-org",
    "INPUT_OUTPUT_FILE": "sonar-results.sarif",
    "INPUT_SEVERITY_FILTER": "MAJOR",
}


class FakeResponse:
    def __init__(self, status_code=200, payload=None, text=""):
        self.status_code = status_code
        self.ok = status_code < 400
        self._payload = payload or {}
        self.text = text or json.dumps(self._payload)

    def json(self):
        return self._payload


def make_issue(rule="python:S1234", severity="MAJOR", component="my-project:src/app.py", line=42, message="Something is wrong", issue_type="CODE_SMELL"):
    return {
        "rule": rule,
        "severity": severity,
        "component": component,
        "line": line,
        "message": message,
        "type": issue_type,
        "textRange": {"startLine": line, "endLine": line},
    }


def make_page(issues=None, total=None, page_size=500, components=None):
    issues = issues if issues is not None else [make_issue()]
    return {
        "issues": issues,
        "components": components if components is not None else [
            {"key": "my-project:src/app.py", "path": "src/app.py"}
        ],
        "paging": {"total": total if total is not None else len(issues), "pageSize": page_size, "pageIndex": 1},
    }


# --- severity_meets_threshold ---

def test_severity_meets_threshold_equal():
    assert scan.severity_meets_threshold("MAJOR", "MAJOR") is True

def test_severity_meets_threshold_more_severe():
    assert scan.severity_meets_threshold("BLOCKER", "MAJOR") is True

def test_severity_meets_threshold_less_severe():
    assert scan.severity_meets_threshold("MINOR", "MAJOR") is False

def test_severity_meets_threshold_unknown_treated_as_info():
    assert scan.severity_meets_threshold("WEIRD", "INFO") is True
    assert scan.severity_meets_threshold("WEIRD", "MAJOR") is False


# --- convert_to_sarif ---

def test_convert_produces_valid_sarif_structure():
    sarif = scan.convert_to_sarif([make_issue()], {"my-project:src/app.py": "src/app.py"}, "https://sonarcloud.io")
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    assert run["tool"]["driver"]["name"] == "SonarQube"
    assert len(run["results"]) == 1
    assert len(run["tool"]["driver"]["rules"]) == 1

def test_convert_rule_id_from_rule_key():
    sarif = scan.convert_to_sarif([make_issue(rule="java:S999")], {}, "https://sonarcloud.io")
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "java:S999"

def test_convert_blocker_maps_to_error():
    sarif = scan.convert_to_sarif([make_issue(severity="BLOCKER")], {}, "https://sonarcloud.io")
    assert sarif["runs"][0]["results"][0]["level"] == "error"

def test_convert_critical_maps_to_error():
    sarif = scan.convert_to_sarif([make_issue(severity="CRITICAL")], {}, "https://sonarcloud.io")
    assert sarif["runs"][0]["results"][0]["level"] == "error"

def test_convert_major_maps_to_warning():
    sarif = scan.convert_to_sarif([make_issue(severity="MAJOR")], {}, "https://sonarcloud.io")
    assert sarif["runs"][0]["results"][0]["level"] == "warning"

def test_convert_minor_maps_to_note():
    sarif = scan.convert_to_sarif([make_issue(severity="MINOR")], {}, "https://sonarcloud.io")
    assert sarif["runs"][0]["results"][0]["level"] == "note"

def test_convert_info_maps_to_note():
    sarif = scan.convert_to_sarif([make_issue(severity="INFO")], {}, "https://sonarcloud.io")
    assert sarif["runs"][0]["results"][0]["level"] == "note"

def test_convert_security_severity_blocker():
    sarif = scan.convert_to_sarif([make_issue(severity="BLOCKER")], {}, "https://sonarcloud.io")
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.0"

def test_convert_result_uri_resolved_from_components_map():
    sarif = scan.convert_to_sarif(
        [make_issue(component="my-project:src/app.py")],
        {"my-project:src/app.py": "src/app.py"},
        "https://sonarcloud.io",
    )
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/app.py"

def test_convert_result_uri_falls_back_to_component_key():
    sarif = scan.convert_to_sarif([make_issue(component="my-project:src/missing.py")], {}, "https://sonarcloud.io")
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "my-project:src/missing.py"

def test_convert_result_line_from_text_range():
    sarif = scan.convert_to_sarif([make_issue(line=99)], {}, "https://sonarcloud.io")
    region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 99

def test_convert_deduplicates_rules_across_issues():
    issues = [make_issue(rule="python:S1234", component="a.py"), make_issue(rule="python:S1234", component="b.py")]
    sarif = scan.convert_to_sarif(issues, {}, "https://sonarcloud.io")
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2

def test_convert_help_uri_links_to_sonar_rule_page():
    sarif = scan.convert_to_sarif([make_issue(rule="python:S1234")], {}, "https://sonar.example.com")
    help_uri = sarif["runs"][0]["tool"]["driver"]["rules"][0]["helpUri"]
    assert help_uri == "https://sonar.example.com/coding_rules?open=python:S1234&rule_key=python:S1234"

def test_convert_empty_issues_produces_no_results():
    sarif = scan.convert_to_sarif([], {}, "https://sonarcloud.io")
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []


# --- fetch_all_issues ---

def test_fetch_all_issues_single_page():
    with patch.object(scan.requests.Session, "get", return_value=FakeResponse(payload=make_page())):
        session = scan.requests.Session()
        issues, components = scan.fetch_all_issues(session, "https://sonarcloud.io", "my-project", "my-org")
    assert len(issues) == 1
    assert components["my-project:src/app.py"] == "src/app.py"

def test_fetch_all_issues_paginates():
    page1 = make_page(issues=[make_issue(rule="r1")], total=2, page_size=1)
    page2 = make_page(issues=[make_issue(rule="r2")], total=2, page_size=1)
    with patch.object(scan.requests.Session, "get", side_effect=[FakeResponse(payload=page1), FakeResponse(payload=page2)]):
        session = scan.requests.Session()
        issues, _ = scan.fetch_all_issues(session, "https://sonarcloud.io", "my-project", None)
    assert len(issues) == 2

def test_fetch_all_issues_401_exits(capsys):
    with patch.object(scan.requests.Session, "get", return_value=FakeResponse(status_code=401)):
        session = scan.requests.Session()
        with pytest.raises(SystemExit) as exc:
            scan.fetch_all_issues(session, "https://sonarcloud.io", "my-project", None)
    assert exc.value.code == 1
    assert "invalid or expired" in capsys.readouterr().err

def test_fetch_all_issues_403_exits(capsys):
    with patch.object(scan.requests.Session, "get", return_value=FakeResponse(status_code=403)):
        session = scan.requests.Session()
        with pytest.raises(SystemExit) as exc:
            scan.fetch_all_issues(session, "https://sonarcloud.io", "my-project", None)
    assert exc.value.code == 1
    assert "permission" in capsys.readouterr().err

def test_fetch_all_issues_404_exits(capsys):
    with patch.object(scan.requests.Session, "get", return_value=FakeResponse(status_code=404)):
        session = scan.requests.Session()
        with pytest.raises(SystemExit) as exc:
            scan.fetch_all_issues(session, "https://sonarcloud.io", "my-project", None)
    assert exc.value.code == 1
    assert "not found" in capsys.readouterr().err


# --- main: input validation ---

def test_main_missing_token(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SONAR_TOKEN": ""}, clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "sonar_token" in capsys.readouterr().err

def test_main_missing_project_key(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_PROJECT_KEY": ""}, clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "project_key" in capsys.readouterr().err

def test_main_invalid_severity_filter(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_SEVERITY_FILTER": "URGENT"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            scan.main()
    assert exc.value.code == 2
    assert "severity_filter" in capsys.readouterr().err


# --- main: execution paths ---

def test_main_happy_path_writes_sarif(tmp_path, capsys):
    out = tmp_path / "out.sarif"
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(out)}
    with patch.dict(os.environ, env, clear=True):
        with patch.object(scan.requests.Session, "get", return_value=FakeResponse(payload=make_page())):
            with pytest.raises(SystemExit) as exc:
                scan.main()
    assert exc.value.code == 0
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1
    assert "Wrote SARIF" in capsys.readouterr().out

def test_main_severity_filter_drops_low_severity_issues(tmp_path):
    out = tmp_path / "out.sarif"
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(out), "INPUT_SEVERITY_FILTER": "CRITICAL"}
    page = make_page(issues=[make_issue(severity="MAJOR"), make_issue(severity="BLOCKER")], total=2)
    with patch.dict(os.environ, env, clear=True):
        with patch.object(scan.requests.Session, "get", return_value=FakeResponse(payload=page)):
            with pytest.raises(SystemExit) as exc:
                scan.main()
    assert exc.value.code == 0
    sarif = json.loads(out.read_text())
    assert len(sarif["runs"][0]["results"]) == 1

def test_main_organization_omitted_for_self_hosted(tmp_path):
    out = tmp_path / "out.sarif"
    env = {**BASE_ENV, "INPUT_OUTPUT_FILE": str(out), "INPUT_ORGANIZATION": ""}
    captured_params = {}

    def fake_get(self, url, params=None, **kwargs):
        captured_params.update(params or {})
        return FakeResponse(payload=make_page())

    with patch.dict(os.environ, env, clear=True):
        with patch.object(scan.requests.Session, "get", fake_get):
            with pytest.raises(SystemExit):
                scan.main()
    assert "organization" not in captured_params
