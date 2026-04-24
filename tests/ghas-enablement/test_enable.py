import os
import sys
from unittest.mock import MagicMock, call, patch

import pytest
import requests

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../actions/ghas-enablement/src"))
import enable


def make_response(status_code=200, json_data=None, links=None):
    resp = MagicMock(spec=requests.Response)
    resp.status_code = status_code
    resp.ok = 200 <= status_code < 300
    resp.json.return_value = json_data if json_data is not None else {}
    resp.links = links or {}
    resp.text = str(json_data)
    return resp


def mock_session(responses: dict):
    """Build a mock session where responses are keyed by (method, url_substring)."""
    session = MagicMock()

    def get_side_effect(url, **kwargs):
        for key, resp in responses.items():
            if key in url:
                return resp
        return make_response(404)

    def put_side_effect(url, **kwargs):
        for key, resp in responses.items():
            if key in url:
                return resp
        return make_response(204)

    def patch_side_effect(url, **kwargs):
        for key, resp in responses.items():
            if key in url:
                return resp
        return make_response(200, {})

    session.get.side_effect = get_side_effect
    session.put.side_effect = put_side_effect
    session.patch.side_effect = patch_side_effect
    return session


# --- parse_bool ---

def test_parse_bool_true_values():
    for v in ("true", "True", "TRUE", "1", "yes"):
        assert enable.parse_bool(v) is True

def test_parse_bool_false_values():
    for v in ("false", "False", "FALSE", "0", "no", ""):
        assert enable.parse_bool(v) is False


# --- codeql_workflow_content ---

def test_codeql_workflow_has_language():
    content = enable.codeql_workflow_content("python")
    assert "languages: python" in content
    assert 'category: "/language:python"' in content

def test_codeql_workflow_with_config():
    content = enable.codeql_workflow_content("java-kotlin", ".github/codeql-config.yml")
    assert "config-file: .github/codeql-config.yml" in content

def test_codeql_workflow_without_config():
    content = enable.codeql_workflow_content("go")
    assert "config-file" not in content


# --- get_repo_info ---

def test_get_repo_info_returns_fields():
    session = MagicMock()
    session.get.return_value = make_response(200, {
        "language": "Python",
        "default_branch": "main",
        "security_and_analysis": {
            "secret_scanning": {"status": "enabled"},
        },
    })
    result = enable.get_repo_info(session, "foo", "bar")
    assert result["language"] == "Python"
    assert result["default_branch"] == "main"
    assert result["secret_scanning"] is True

def test_get_repo_info_returns_none_on_failure():
    session = MagicMock()
    session.get.return_value = make_response(404)
    assert enable.get_repo_info(session, "foo", "bar") is None

def test_get_repo_info_secret_scanning_disabled():
    session = MagicMock()
    session.get.return_value = make_response(200, {
        "language": "Java",
        "default_branch": "master",
        "security_and_analysis": {
            "secret_scanning": {"status": "disabled"},
        },
    })
    result = enable.get_repo_info(session, "foo", "bar")
    assert result["secret_scanning"] is False


# --- get_dependabot_state ---

def test_get_dependabot_state_enabled():
    session = MagicMock()
    session.get.side_effect = [
        make_response(204),  # vulnerability-alerts: 204 = enabled
        make_response(200, {"enabled": True}),  # automated-security-fixes
    ]
    result = enable.get_dependabot_state(session, "foo", "bar")
    assert result["dependabot_alerts"] is True
    assert result["dependabot_updates"] is True

def test_get_dependabot_state_disabled():
    session = MagicMock()
    session.get.side_effect = [
        make_response(404),  # vulnerability-alerts: 404 = disabled
        make_response(200, {"enabled": False}),
    ]
    result = enable.get_dependabot_state(session, "foo", "bar")
    assert result["dependabot_alerts"] is False
    assert result["dependabot_updates"] is False


# --- get_code_scanning_state ---

def test_get_code_scanning_state_present():
    session = MagicMock()
    session.get.return_value = make_response(200, {"name": "codeql.yml"})
    assert enable.get_code_scanning_state(session, "foo", "bar") is True

def test_get_code_scanning_state_absent():
    session = MagicMock()
    session.get.return_value = make_response(404)
    assert enable.get_code_scanning_state(session, "foo", "bar") is False


# --- deploy_file ---

def test_deploy_file_new_file():
    session = MagicMock()
    session.get.return_value = make_response(404)  # file doesn't exist
    session.put.return_value = make_response(201, {})
    enable.deploy_file(session, "foo", "bar", ".github/workflows/codeql.yml", "content", "msg", "main")
    call_args = session.put.call_args
    assert "sha" not in call_args.kwargs.get("json", {})

def test_deploy_file_update_existing():
    session = MagicMock()
    session.get.return_value = make_response(200, {"sha": "abc123"})
    session.put.return_value = make_response(200, {})
    enable.deploy_file(session, "foo", "bar", ".github/workflows/codeql.yml", "content", "msg", "main")
    call_args = session.put.call_args
    assert call_args.kwargs["json"]["sha"] == "abc123"

def test_deploy_file_raises_on_failure():
    session = MagicMock()
    session.get.return_value = make_response(404)
    session.put.return_value = make_response(422, {"message": "Unprocessable"})
    with pytest.raises(RuntimeError, match="422"):
        enable.deploy_file(session, "foo", "bar", "path", "content", "msg", "main")


# --- enable_repo ---

def _make_full_session(secret_scanning=False, dependabot_alerts=False, dependabot_updates=False, code_scanning=False, language="Python"):
    session = MagicMock()

    def get_side(url, **kwargs):
        if "/vulnerability-alerts" in url:
            return make_response(204 if dependabot_alerts else 404)
        if "/automated-security-fixes" in url:
            return make_response(200, {"enabled": dependabot_updates})
        if "codeql.yml" in url and "/contents/" in url:
            return make_response(200 if code_scanning else 404)
        if "/repos/" in url and url.endswith(tuple(["foo/bar", "foo/baz"])):
            return make_response(200, {
                "language": language,
                "default_branch": "main",
                "security_and_analysis": {
                    "secret_scanning": {"status": "enabled" if secret_scanning else "disabled"},
                },
            })
        return make_response(404)

    session.get.side_effect = get_side
    session.put.return_value = make_response(204)
    session.patch.return_value = make_response(200, {})
    return session


def test_enable_repo_dry_run_shows_would_enable():
    session = _make_full_session()
    results = enable.enable_repo(session, "foo", "bar", {
        "dependabot_alerts": True, "dependabot_updates": True,
        "secret_scanning": True, "code_scanning": True,
    }, dry_run=True, code_scanning_config_content=None)
    assert all(v == "would enable" for v in results.values())
    session.put.assert_not_called()
    session.patch.assert_not_called()

def test_enable_repo_already_enabled():
    session = _make_full_session(
        secret_scanning=True, dependabot_alerts=True,
        dependabot_updates=True, code_scanning=True,
    )
    results = enable.enable_repo(session, "foo", "bar", {
        "dependabot_alerts": True, "dependabot_updates": True,
        "secret_scanning": True, "code_scanning": True,
    }, dry_run=False, code_scanning_config_content=None)
    assert all(v == "already enabled" for v in results.values())
    session.put.assert_not_called()

def test_enable_repo_enables_missing_features():
    session = _make_full_session()
    with patch.object(enable, "deploy_file"):
        results = enable.enable_repo(session, "foo", "bar", {
            "dependabot_alerts": True, "dependabot_updates": True,
            "secret_scanning": True, "code_scanning": True,
        }, dry_run=False, code_scanning_config_content=None)
    assert results["dependabot_alerts"] == "enabled"
    assert results["secret_scanning"] == "enabled"
    assert results["code_scanning"] == "enabled"

def test_enable_repo_skips_unrequested_features():
    session = _make_full_session()
    results = enable.enable_repo(session, "foo", "bar", {
        "dependabot_alerts": True, "dependabot_updates": False,
        "secret_scanning": False, "code_scanning": False,
    }, dry_run=False, code_scanning_config_content=None)
    assert results["dependabot_updates"] == "skipped"
    assert results["secret_scanning"] == "skipped"
    assert results["code_scanning"] == "skipped"

def test_enable_repo_unsupported_language():
    session = _make_full_session(language="COBOL")
    results = enable.enable_repo(session, "foo", "bar", {
        "dependabot_alerts": False, "dependabot_updates": False,
        "secret_scanning": False, "code_scanning": True,
    }, dry_run=False, code_scanning_config_content=None)
    assert results["code_scanning"].startswith("error")

def test_enable_repo_returns_error_on_info_failure():
    session = MagicMock()
    session.get.return_value = make_response(404)
    results = enable.enable_repo(session, "foo", "bar", {
        "dependabot_alerts": True, "dependabot_updates": True,
        "secret_scanning": True, "code_scanning": True,
    }, dry_run=False, code_scanning_config_content=None)
    assert all(v.startswith("error") for v in results.values())


# --- print_summary ---

def test_print_summary_counts(capsys):
    all_results = {
        "foo/bar": {"dependabot_alerts": "enabled", "secret_scanning": "already enabled"},
        "foo/baz": {"dependabot_alerts": "error: 403", "secret_scanning": "would enable"},
    }
    enable.print_summary(all_results)
    out = capsys.readouterr().out
    assert "enabled: 1" in out
    assert "already enabled: 1" in out
    assert "would enable: 1" in out


# --- main validation ---

def test_main_missing_token_exits_2():
    with patch.dict(os.environ, {"INPUT_TARGET": "foo/bar", "INPUT_TARGET_TYPE": "repo"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            enable.main()
    assert exc.value.code == 2

def test_main_missing_target_exits_2():
    with patch.dict(os.environ, {"INPUT_TOKEN": "ghp_xxx", "INPUT_TARGET_TYPE": "repo"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            enable.main()
    assert exc.value.code == 2

def test_main_invalid_target_type_exits_2():
    env = {"INPUT_TOKEN": "ghp_xxx", "INPUT_TARGET": "foo/bar", "INPUT_TARGET_TYPE": "cluster"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            enable.main()
    assert exc.value.code == 2

def test_main_bad_repo_format_exits_2():
    env = {"INPUT_TOKEN": "ghp_xxx", "INPUT_TARGET": "notvalid", "INPUT_TARGET_TYPE": "repo"}
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            enable.main()
    assert exc.value.code == 2

def test_main_missing_config_file_exits_2():
    env = {
        "INPUT_TOKEN": "ghp_xxx", "INPUT_TARGET": "foo/bar",
        "INPUT_TARGET_TYPE": "repo", "INPUT_CODE_SCANNING_CONFIG": "/nonexistent/config.yml",
    }
    with patch.dict(os.environ, env, clear=True):
        with pytest.raises(SystemExit) as exc:
            enable.main()
    assert exc.value.code == 2

def test_main_repo_dry_run(capsys):
    env = {
        "INPUT_TOKEN": "ghp_xxx", "INPUT_TARGET": "foo/bar",
        "INPUT_TARGET_TYPE": "repo", "INPUT_DRY_RUN": "true",
        "INPUT_ENABLE_CODE_SCANNING": "true", "INPUT_ENABLE_SECRET_SCANNING": "true",
        "INPUT_ENABLE_DEPENDABOT_ALERTS": "true", "INPUT_ENABLE_DEPENDABOT_UPDATES": "true",
        "INPUT_CODE_SCANNING_CONFIG": "",
    }
    session = _make_full_session()
    with patch("requests.Session", return_value=session):
        with patch.dict(os.environ, env, clear=True):
            enable.main()
    out = capsys.readouterr().out
    assert "DRY RUN" in out
    assert "would enable" in out
