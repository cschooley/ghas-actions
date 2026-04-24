import csv
import json
import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../actions/findings-exporter/src"))
import export


def make_response(status_code=200, json_data=None, links=None):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 300
    resp.json.return_value = json_data if json_data is not None else []
    resp.links = links or {}
    resp.text = json.dumps(json_data) if json_data else ""
    return resp


# --- severity_meets_threshold ---

def test_severity_no_filter():
    assert export.severity_meets_threshold("low", None) is True

def test_severity_exact_match():
    assert export.severity_meets_threshold("high", "high") is True

def test_severity_above_threshold():
    assert export.severity_meets_threshold("critical", "high") is True

def test_severity_below_threshold():
    assert export.severity_meets_threshold("low", "high") is False

def test_severity_unknown_included_conservatively():
    assert export.severity_meets_threshold("unknown", "high") is True

def test_severity_none_included_conservatively():
    assert export.severity_meets_threshold(None, "high") is True


# --- check_response ---

def test_check_response_ok():
    export.check_response(make_response(200))

def test_check_response_401(capsys):
    with pytest.raises(SystemExit) as exc:
        export.check_response(make_response(401))
    assert exc.value.code == 1
    assert "invalid or expired" in capsys.readouterr().err

def test_check_response_403_mentions_scope(capsys):
    with pytest.raises(SystemExit) as exc:
        export.check_response(make_response(403))
    assert exc.value.code == 1
    assert "security_events" in capsys.readouterr().err

def test_check_response_404_mentions_ghas(capsys):
    with pytest.raises(SystemExit) as exc:
        export.check_response(make_response(404))
    assert exc.value.code == 1
    assert "GHAS" in capsys.readouterr().err

def test_check_response_500_exits_1(capsys):
    resp = make_response(500)
    resp.text = "Internal Server Error"
    with pytest.raises(SystemExit) as exc:
        export.check_response(resp)
    assert exc.value.code == 1


# --- paginate ---

def test_paginate_single_page():
    session = MagicMock()
    session.get.return_value = make_response(200, [{"id": 1}, {"id": 2}])
    result = export.paginate(session, "https://api.github.com/test", {"per_page": 100})
    assert result == [{"id": 1}, {"id": 2}]
    session.get.assert_called_once()

def test_paginate_follows_next_link():
    session = MagicMock()
    page1 = make_response(200, [{"id": 1}], links={"next": {"url": "https://api.github.com/test?page=2"}})
    page2 = make_response(200, [{"id": 2}])
    session.get.side_effect = [page1, page2]
    result = export.paginate(session, "https://api.github.com/test", {"per_page": 100})
    assert result == [{"id": 1}, {"id": 2}]
    assert session.get.call_count == 2


# --- state_param ---

def test_state_param_all_returns_empty():
    assert export.state_param("code_scanning", "all") == {}

def test_state_param_open():
    assert export.state_param("code_scanning", "open") == {"state": "open"}

def test_state_param_secret_scanning_fixed_maps_to_resolved():
    assert export.state_param("secret_scanning", "fixed") == {"state": "resolved"}

def test_state_param_secret_scanning_dismissed_maps_to_resolved():
    assert export.state_param("secret_scanning", "dismissed") == {"state": "resolved"}

def test_state_param_secret_scanning_open_unchanged():
    assert export.state_param("secret_scanning", "open") == {"state": "open"}


# --- normalize_code_scanning ---

def test_normalize_code_scanning_fields():
    alert = {
        "number": 42,
        "state": "open",
        "rule": {"id": "py/sqli", "name": "SQL Injection", "security_severity_level": "high"},
        "most_recent_instance": {"location": {"path": "app.py", "start_line": 10}},
        "html_url": "https://github.com/foo/bar/security/code-scanning/42",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    result = export.normalize_code_scanning(alert, "foo/bar")
    assert result["composite_key"] == "ghas:code_scanning:foo/bar:42"
    assert result["severity"] == "high"
    assert result["file"] == "app.py"
    assert result["line"] == 10
    assert result["alert_type"] == "code_scanning"

def test_normalize_code_scanning_falls_back_to_rule_severity():
    alert = {
        "number": 1, "state": "open",
        "rule": {"id": "r", "severity": "medium"},
        "most_recent_instance": {"location": {}},
        "html_url": "", "created_at": "", "updated_at": "",
    }
    assert export.normalize_code_scanning(alert, "o/r")["severity"] == "medium"


# --- normalize_secret_scanning ---

def test_normalize_secret_scanning_severity_is_critical():
    alert = {
        "number": 5, "state": "open",
        "secret_type": "github_personal_access_token",
        "secret_type_display_name": "GitHub Personal Access Token",
        "html_url": "https://github.com/foo/bar/security/secret-scanning/5",
        "created_at": "2026-01-01T00:00:00Z",
        "updated_at": "2026-01-01T00:00:00Z",
    }
    result = export.normalize_secret_scanning(alert, "foo/bar")
    assert result["severity"] == "critical"
    assert result["composite_key"] == "ghas:secret_scanning:foo/bar:5"
    assert result["file"] is None
    assert result["line"] is None


# --- normalize_dependabot ---

def test_normalize_dependabot_uses_cve_id():
    alert = {
        "number": 3, "state": "open",
        "security_advisory": {
            "cve_id": "CVE-2024-1234", "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "severity": "critical", "summary": "RCE", "description": "...",
        },
        "dependency": {"manifest_path": "package.json"},
        "html_url": "", "created_at": "", "updated_at": "",
    }
    result = export.normalize_dependabot(alert, "foo/bar")
    assert result["rule_id"] == "CVE-2024-1234"
    assert result["severity"] == "critical"
    assert result["file"] == "package.json"

def test_normalize_dependabot_falls_back_to_ghsa():
    alert = {
        "number": 4, "state": "open",
        "security_advisory": {
            "cve_id": None, "ghsa_id": "GHSA-xxxx-yyyy-zzzz",
            "severity": "high", "summary": "Vuln", "description": "desc",
        },
        "dependency": {"manifest_path": "requirements.txt"},
        "html_url": "", "created_at": "", "updated_at": "",
    }
    assert export.normalize_dependabot(alert, "o/r")["rule_id"] == "GHSA-xxxx-yyyy-zzzz"


# --- write_output ---

def test_write_json_output(tmp_path):
    findings = [{"source": "ghas", "alert_id": 1, "severity": "high"}]
    out = tmp_path / "findings.json"
    export.write_output(findings, "json", str(out))
    assert json.loads(out.read_text())[0]["alert_id"] == 1

def test_write_csv_output(tmp_path):
    findings = [{
        "source": "ghas", "alert_type": "code_scanning", "alert_id": 1,
        "composite_key": "ghas:code_scanning:o/r:1", "severity": "high",
        "state": "open", "rule_id": "r", "rule_name": "Rule", "description": "desc",
        "file": "app.py", "line": 10, "url": "https://example.com",
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
    }]
    out = tmp_path / "findings.csv"
    export.write_output(findings, "csv", str(out))
    rows = list(csv.DictReader(out.read_text().splitlines()))
    assert len(rows) == 1
    assert rows[0]["alert_id"] == "1"

def test_write_csv_empty_writes_header(tmp_path):
    out = tmp_path / "findings.csv"
    export.write_output([], "csv", str(out))
    lines = out.read_text().splitlines()
    assert len(lines) == 1
    assert "composite_key" in lines[0]


# --- main: input validation ---

def test_main_missing_token_exits_2():
    with patch.dict(os.environ, {"INPUT_REPO": "foo/bar"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            export.main()
    assert exc.value.code == 2

def test_main_missing_repo_exits_2():
    with patch.dict(os.environ, {"INPUT_TOKEN": "ghp_xxx"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            export.main()
    assert exc.value.code == 2

def test_main_bad_repo_format_exits_2():
    with patch.dict(os.environ, {"INPUT_TOKEN": "ghp_xxx", "INPUT_REPO": "notvalid"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            export.main()
    assert exc.value.code == 2

def test_main_invalid_alert_type_exits_2():
    env = {"INPUT_TOKEN": "ghp_xxx", "INPUT_REPO": "foo/bar", "INPUT_ALERT_TYPES": "fake_type"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            export.main()
    assert exc.value.code == 2

def test_main_invalid_state_exits_2():
    env = {"INPUT_TOKEN": "ghp_xxx", "INPUT_REPO": "foo/bar", "INPUT_STATE": "unknown"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            export.main()
    assert exc.value.code == 2

def test_main_invalid_format_exits_2():
    env = {"INPUT_TOKEN": "ghp_xxx", "INPUT_REPO": "foo/bar", "INPUT_OUTPUT_FORMAT": "xml"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            export.main()
    assert exc.value.code == 2

def test_main_invalid_severity_filter_exits_2():
    env = {"INPUT_TOKEN": "ghp_xxx", "INPUT_REPO": "foo/bar", "INPUT_SEVERITY_FILTER": "extreme"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            export.main()
    assert exc.value.code == 2


# --- main: happy paths ---

def test_main_happy_path(tmp_path):
    out = tmp_path / "findings.json"
    env = {
        "INPUT_TOKEN": "ghp_xxx", "INPUT_REPO": "foo/bar",
        "INPUT_ALERT_TYPES": "code_scanning", "INPUT_STATE": "open",
        "INPUT_OUTPUT_FORMAT": "json", "INPUT_OUTPUT_FILE": str(out),
        "INPUT_SEVERITY_FILTER": "",
    }
    alert = {
        "number": 1, "state": "open",
        "rule": {"id": "py/sqli", "name": "SQL Injection", "security_severity_level": "high"},
        "most_recent_instance": {"location": {"path": "app.py", "start_line": 10}},
        "html_url": "https://github.com/foo/bar/security/code-scanning/1",
        "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z",
    }
    with patch("requests.Session") as MockSession:
        MockSession.return_value.get.return_value = make_response(200, [alert])
        with patch.dict(os.environ, env, clear=True):
            export.main()
    data = json.loads(out.read_text())
    assert len(data) == 1
    assert data[0]["composite_key"] == "ghas:code_scanning:foo/bar:1"

def test_main_empty_results(tmp_path):
    out = tmp_path / "findings.json"
    env = {
        "INPUT_TOKEN": "ghp_xxx", "INPUT_REPO": "foo/bar",
        "INPUT_ALERT_TYPES": "code_scanning", "INPUT_STATE": "open",
        "INPUT_OUTPUT_FORMAT": "json", "INPUT_OUTPUT_FILE": str(out),
        "INPUT_SEVERITY_FILTER": "",
    }
    with patch("requests.Session") as MockSession:
        MockSession.return_value.get.return_value = make_response(200, [])
        with patch.dict(os.environ, env, clear=True):
            export.main()
    assert json.loads(out.read_text()) == []

def test_main_severity_filter_applied(tmp_path):
    out = tmp_path / "findings.json"
    env = {
        "INPUT_TOKEN": "ghp_xxx", "INPUT_REPO": "foo/bar",
        "INPUT_ALERT_TYPES": "code_scanning", "INPUT_STATE": "open",
        "INPUT_OUTPUT_FORMAT": "json", "INPUT_OUTPUT_FILE": str(out),
        "INPUT_SEVERITY_FILTER": "high",
    }
    alerts = [
        {
            "number": 1, "state": "open",
            "rule": {"id": "r1", "security_severity_level": "critical"},
            "most_recent_instance": {"location": {}},
            "html_url": "", "created_at": "", "updated_at": "",
        },
        {
            "number": 2, "state": "open",
            "rule": {"id": "r2", "security_severity_level": "low"},
            "most_recent_instance": {"location": {}},
            "html_url": "", "created_at": "", "updated_at": "",
        },
    ]
    with patch("requests.Session") as MockSession:
        MockSession.return_value.get.return_value = make_response(200, alerts)
        with patch.dict(os.environ, env, clear=True):
            export.main()
    data = json.loads(out.read_text())
    assert len(data) == 1
    assert data[0]["alert_id"] == 1
