import os
import sys
from unittest.mock import MagicMock, patch

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../actions/dependency-review-gate/src"))
import gate


def make_response(status_code=200, json_data=None):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 300
    resp.json.return_value = json_data if json_data is not None else []
    resp.text = str(json_data or "")
    return resp


def make_change(name="pkg", version="1.0.0", ecosystem="npm", change_type="added",
                license_id=None, vulnerabilities=None):
    c = {
        "name": name,
        "version": version,
        "ecosystem": ecosystem,
        "change_type": change_type,
        "license": license_id,
        "vulnerabilities": vulnerabilities or [],
    }
    return c


def make_vuln(severity="high", ghsa_id="GHSA-xxxx-yyyy-zzzz"):
    return {"severity": severity, "advisory_ghsa_id": ghsa_id, "advisory_summary": ""}


# --- severity_meets_threshold ---

def test_severity_critical_meets_critical():
    assert gate.severity_meets_threshold("critical", "critical") is True

def test_severity_critical_meets_high():
    assert gate.severity_meets_threshold("critical", "high") is True

def test_severity_high_meets_high():
    assert gate.severity_meets_threshold("high", "high") is True

def test_severity_medium_does_not_meet_high():
    assert gate.severity_meets_threshold("medium", "high") is False

def test_severity_low_does_not_meet_high():
    assert gate.severity_meets_threshold("low", "high") is False

def test_severity_unknown_returns_false():
    assert gate.severity_meets_threshold("unknown", "high") is False

def test_severity_none_returns_false():
    assert gate.severity_meets_threshold(None, "high") is False

def test_severity_invalid_threshold_returns_false():
    assert gate.severity_meets_threshold("high", "extreme") is False


# --- parse_list ---

def test_parse_list_basic():
    assert gate.parse_list("MIT, Apache-2.0, BSD-2-Clause") == ["MIT", "Apache-2.0", "BSD-2-Clause"]

def test_parse_list_empty():
    assert gate.parse_list("") == []

def test_parse_list_single():
    assert gate.parse_list("GPL-2.0") == ["GPL-2.0"]

def test_parse_list_strips_whitespace():
    assert gate.parse_list("  MIT  ,  Apache-2.0  ") == ["MIT", "Apache-2.0"]


# --- check_response ---

def test_check_response_ok():
    gate.check_response(make_response(200), "test")

def test_check_response_401(capsys):
    with pytest.raises(SystemExit) as exc:
        gate.check_response(make_response(401), "test context")
    assert exc.value.code == 1
    assert "invalid or expired" in capsys.readouterr().err

def test_check_response_403(capsys):
    with pytest.raises(SystemExit) as exc:
        gate.check_response(make_response(403), "test context")
    assert exc.value.code == 1
    assert "lacks permissions" in capsys.readouterr().err

def test_check_response_404(capsys):
    with pytest.raises(SystemExit) as exc:
        gate.check_response(make_response(404), "test context")
    assert exc.value.code == 1
    assert "Not found" in capsys.readouterr().err

def test_check_response_500(capsys):
    with pytest.raises(SystemExit) as exc:
        gate.check_response(make_response(500), "test context")
    assert exc.value.code == 1


# --- evaluate_changes ---

def test_evaluate_no_changes():
    violations, ignored = gate.evaluate_changes([], "high", [], [], [])
    assert violations == []
    assert ignored == []

def test_evaluate_skips_removed():
    change = make_change(change_type="removed")
    change["vulnerabilities"] = [make_vuln("critical")]
    violations, ignored = gate.evaluate_changes([change], "high", [], [], [])
    assert violations == []

def test_evaluate_vulnerability_above_threshold():
    change = make_change(vulnerabilities=[make_vuln("high")])
    violations, ignored = gate.evaluate_changes([change], "high", [], [], [])
    assert len(violations) == 1
    assert violations[0]["reason"] == "vulnerability (high)"
    assert violations[0]["package"] == "pkg"

def test_evaluate_vulnerability_below_threshold():
    change = make_change(vulnerabilities=[make_vuln("medium")])
    violations, ignored = gate.evaluate_changes([change], "high", [], [], [])
    assert violations == []

def test_evaluate_critical_meets_medium_threshold():
    change = make_change(vulnerabilities=[make_vuln("critical")])
    violations, ignored = gate.evaluate_changes([change], "medium", [], [], [])
    assert len(violations) == 1

def test_evaluate_cve_ignored():
    change = make_change(vulnerabilities=[make_vuln("critical", "GHSA-ignore-me")])
    violations, ignored = gate.evaluate_changes([change], "high", [], [], ["GHSA-ignore-me"])
    assert violations == []
    assert len(ignored) == 1
    assert ignored[0]["cve"] == "GHSA-ignore-me"
    assert ignored[0]["reason"] == "CVE ignored"

def test_evaluate_deny_license_no_vuln():
    change = make_change(license_id="GPL-2.0")
    violations, ignored = gate.evaluate_changes([change], "high", [], ["GPL-2.0"], [])
    assert len(violations) == 1
    assert violations[0]["reason"] == "denied license"

def test_evaluate_deny_license_not_matched():
    change = make_change(license_id="MIT")
    violations, ignored = gate.evaluate_changes([change], "high", [], ["GPL-2.0"], [])
    assert violations == []

def test_evaluate_allow_license_passes():
    change = make_change(license_id="MIT")
    violations, ignored = gate.evaluate_changes([change], "high", ["MIT", "Apache-2.0"], [], [])
    assert violations == []

def test_evaluate_allow_license_fails():
    change = make_change(license_id="GPL-2.0")
    violations, ignored = gate.evaluate_changes([change], "high", ["MIT", "Apache-2.0"], [], [])
    assert len(violations) == 1
    assert violations[0]["reason"] == "denied license"

def test_evaluate_allow_license_unknown_skipped():
    change = make_change(license_id="unknown")
    violations, ignored = gate.evaluate_changes([change], "high", ["MIT"], [], [])
    assert violations == []

def test_evaluate_license_additive_with_vuln():
    change = make_change(license_id="GPL-2.0", vulnerabilities=[make_vuln("high")])
    violations, ignored = gate.evaluate_changes([change], "high", [], ["GPL-2.0"], [])
    reasons = [v["reason"] for v in violations]
    assert "vulnerability (high)" in reasons
    assert "denied license" in reasons

def test_evaluate_license_additive_no_duplicate():
    change = make_change(license_id="GPL-2.0", vulnerabilities=[make_vuln("high"), make_vuln("medium", "GHSA-2")])
    violations, ignored = gate.evaluate_changes([change], "low", [], ["GPL-2.0"], [])
    license_violations = [v for v in violations if v["reason"] == "denied license"]
    assert len(license_violations) == 1


# --- build_comment ---

def test_build_comment_pass():
    comment = gate.build_comment([], [], passed=True)
    assert "PASSED" in comment
    assert "No vulnerabilities" in comment

def test_build_comment_fail_with_violations():
    violations = [{
        "package": "lodash", "version": "4.17.20", "ecosystem": "npm",
        "severity": "high", "cve": "GHSA-xxxx", "license": "MIT",
        "reason": "vulnerability (high)",
    }]
    comment = gate.build_comment(violations, [], passed=False)
    assert "FAILED" in comment
    assert "lodash" in comment
    assert "GHSA-xxxx" in comment
    assert "Violations" in comment

def test_build_comment_ignored_audit_trail():
    ignored = [{
        "package": "lodash", "version": "4.17.20", "ecosystem": "npm",
        "severity": "high", "cve": "GHSA-audit", "license": "MIT",
        "reason": "CVE ignored",
    }]
    comment = gate.build_comment([], ignored, passed=True)
    assert "Ignored" in comment
    assert "GHSA-audit" in comment

def test_build_comment_none_severity_renders_dash():
    violations = [{
        "package": "badpkg", "version": "1.0", "ecosystem": "npm",
        "severity": None, "cve": None, "license": "GPL-2.0",
        "reason": "denied license",
    }]
    comment = gate.build_comment(violations, [], passed=False)
    assert "—" in comment


# --- post_pr_comment ---

def test_post_pr_comment_success(capsys):
    session = MagicMock()
    session.post.return_value = make_response(201)
    gate.post_pr_comment(session, "owner/repo", 42, "body text")
    session.post.assert_called_once()

def test_post_pr_comment_failure_warns(capsys):
    session = MagicMock()
    session.post.return_value = make_response(403)
    gate.post_pr_comment(session, "owner/repo", 42, "body text")
    assert "WARNING" in capsys.readouterr().err


# --- main input validation ---

BASE_ENV = {
    "INPUT_TOKEN": "ghp_token",
    "INPUT_REPO": "owner/repo",
    "INPUT_BASE_SHA": "abc1234",
    "INPUT_HEAD_SHA": "def5678",
    "INPUT_PR_NUMBER": "",
    "INPUT_FAIL_ON_SEVERITY": "high",
    "INPUT_ALLOW_LICENSES": "",
    "INPUT_DENY_LICENSES": "",
    "INPUT_IGNORE_CVES": "",
    "INPUT_COMMENT_ON_PR": "true",
}

def test_main_missing_token(capsys):
    env = {**BASE_ENV, "INPUT_TOKEN": ""}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            gate.main()
    assert exc.value.code == 2

def test_main_invalid_repo(capsys):
    env = {**BASE_ENV, "INPUT_REPO": "notavalidrepo"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            gate.main()
    assert exc.value.code == 2

def test_main_missing_base_sha(capsys):
    env = {**BASE_ENV, "INPUT_BASE_SHA": ""}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            gate.main()
    assert exc.value.code == 2

def test_main_missing_head_sha(capsys):
    env = {**BASE_ENV, "INPUT_HEAD_SHA": ""}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            gate.main()
    assert exc.value.code == 2

def test_main_invalid_severity(capsys):
    env = {**BASE_ENV, "INPUT_FAIL_ON_SEVERITY": "extreme"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            gate.main()
    assert exc.value.code == 2

def test_main_mutually_exclusive_licenses(capsys):
    env = {**BASE_ENV, "INPUT_ALLOW_LICENSES": "MIT", "INPUT_DENY_LICENSES": "GPL-2.0"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            gate.main()
    assert exc.value.code == 2

def test_main_happy_path_no_violations(capsys):
    env = {**BASE_ENV, "INPUT_COMMENT_ON_PR": "false"}
    with patch.dict(os.environ, env, clear=True):
        with patch("gate.get_dependency_changes", return_value=[]) as mock_get:
            with pytest.raises(SystemExit) as exc:
                gate.main()
    assert exc.value.code == 0
    assert "PASSED" in capsys.readouterr().out

def test_main_happy_path_with_violation(capsys):
    change = make_change(vulnerabilities=[make_vuln("critical")])
    env = {**BASE_ENV, "INPUT_COMMENT_ON_PR": "false"}
    with patch.dict(os.environ, env, clear=True):
        with patch("gate.get_dependency_changes", return_value=[change]):
            with pytest.raises(SystemExit) as exc:
                gate.main()
    assert exc.value.code == 1
    assert "FAILED" in capsys.readouterr().out

def test_main_posts_comment_when_pr_number_set(capsys):
    env = {**BASE_ENV, "INPUT_PR_NUMBER": "7", "INPUT_COMMENT_ON_PR": "true"}
    with patch.dict(os.environ, env, clear=True):
        with patch("gate.get_dependency_changes", return_value=[]):
            with patch("gate.post_pr_comment") as mock_comment:
                with pytest.raises(SystemExit):
                    gate.main()
    mock_comment.assert_called_once()

def test_main_warns_when_comment_true_no_pr(capsys):
    env = {**BASE_ENV, "INPUT_PR_NUMBER": "", "INPUT_COMMENT_ON_PR": "true"}
    with patch.dict(os.environ, env, clear=True):
        with patch("gate.get_dependency_changes", return_value=[]):
            with pytest.raises(SystemExit):
                gate.main()
    assert "WARNING" in capsys.readouterr().err
