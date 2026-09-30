import importlib.util
import json
import os
import sys
from unittest.mock import patch

import pytest

_spec = importlib.util.spec_from_file_location(
    "ai_review",
    os.path.join(os.path.dirname(__file__), "../../actions/ai-pr-reviewer/src/review.py"),
)
review = importlib.util.module_from_spec(_spec)
sys.modules["ai_review"] = review
_spec.loader.exec_module(review)


BASE_ENV = {
    "INPUT_ANTHROPIC_API_KEY": "sk-ant-test",
    "INPUT_GITHUB_TOKEN": "ghp-test",
    "INPUT_REPO": "owner/repo",
    "INPUT_PR_NUMBER": "42",
    "INPUT_MODEL": "claude-haiku-4-5-20251001",
    "INPUT_MODE": "comment",
    "INPUT_OUTPUT_FILE": "ai-review.sarif",
    "INPUT_FAIL_ON_FINDINGS": "false",
    "INPUT_FOCUS": "security",
}

SAMPLE_FINDING = {
    "rule_id": "sql-injection",
    "rule_name": "SQL Injection",
    "severity": "HIGH",
    "file": "src/db.py",
    "line": 10,
    "description": "User input concatenated directly into SQL query.",
    "recommendation": "Use parameterized queries.",
}

SAMPLE_DIFF = "+import os\n+password = 'hunter2'\n+query = 'SELECT * FROM users WHERE id=' + user_id\n"


# --- parse_bool ---

def test_parse_bool_true_values():
    for v in ("true", "True", "1", "yes"):
        assert review.parse_bool(v) is True

def test_parse_bool_false_values():
    for v in ("false", "0", "no", ""):
        assert review.parse_bool(v) is False


# --- truncate_diff ---

def test_truncate_diff_short_diff_unchanged():
    diff = "line\n" * 10
    result, truncated = review.truncate_diff(diff, max_lines=100)
    assert result == diff
    assert truncated is False

def test_truncate_diff_long_diff_truncated():
    diff = "line\n" * 5000
    result, truncated = review.truncate_diff(diff, max_lines=100)
    assert truncated is True
    assert len(result.splitlines()) == 100

def test_truncate_diff_exact_limit_not_truncated():
    diff = "\n".join(["line"] * 100)
    _, truncated = review.truncate_diff(diff, max_lines=100)
    assert truncated is False


# --- build_sarif_prompt ---

def test_build_sarif_prompt_contains_diff():
    prompt = review.build_sarif_prompt(SAMPLE_DIFF, "security")
    assert SAMPLE_DIFF in prompt

def test_build_sarif_prompt_security_focus():
    prompt = review.build_sarif_prompt("diff", "security")
    assert "security" in prompt.lower()

def test_build_sarif_prompt_general_focus():
    prompt = review.build_sarif_prompt("diff", "general")
    assert "quality" in prompt.lower() or "maintainability" in prompt.lower()

def test_build_sarif_prompt_requests_json():
    prompt = review.build_sarif_prompt("diff", "security")
    assert "JSON" in prompt
    assert "findings" in prompt

def test_build_comment_prompt_contains_diff():
    prompt = review.build_comment_prompt(SAMPLE_DIFF, "security")
    assert SAMPLE_DIFF in prompt

def test_build_comment_prompt_requests_markdown():
    prompt = review.build_comment_prompt("diff", "security")
    assert "markdown" in prompt.lower() or "##" in prompt


# --- findings_to_sarif ---

def test_findings_to_sarif_empty():
    sarif = review.findings_to_sarif([], "owner/repo", "1")
    assert sarif["version"] == "2.1.0"
    assert sarif["runs"][0]["results"] == []
    assert sarif["runs"][0]["tool"]["driver"]["rules"] == []

def test_findings_to_sarif_single_finding():
    sarif = review.findings_to_sarif([SAMPLE_FINDING], "owner/repo", "1")
    assert len(sarif["runs"][0]["results"]) == 1
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1

def test_findings_to_sarif_rule_id():
    sarif = review.findings_to_sarif([SAMPLE_FINDING], "owner/repo", "1")
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"] == "sql-injection"

def test_findings_to_sarif_high_severity_maps_to_error():
    sarif = review.findings_to_sarif([SAMPLE_FINDING], "owner/repo", "1")
    assert sarif["runs"][0]["results"][0]["level"] == "error"

def test_findings_to_sarif_critical_maps_to_error():
    f = {**SAMPLE_FINDING, "severity": "CRITICAL"}
    sarif = review.findings_to_sarif([f], "owner/repo", "1")
    assert sarif["runs"][0]["results"][0]["level"] == "error"

def test_findings_to_sarif_medium_maps_to_warning():
    f = {**SAMPLE_FINDING, "severity": "MEDIUM"}
    sarif = review.findings_to_sarif([f], "owner/repo", "1")
    assert sarif["runs"][0]["results"][0]["level"] == "warning"

def test_findings_to_sarif_low_maps_to_note():
    f = {**SAMPLE_FINDING, "severity": "LOW"}
    sarif = review.findings_to_sarif([f], "owner/repo", "1")
    assert sarif["runs"][0]["results"][0]["level"] == "note"

def test_findings_to_sarif_security_severity_high():
    sarif = review.findings_to_sarif([SAMPLE_FINDING], "owner/repo", "1")
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "8.0"

def test_findings_to_sarif_security_severity_critical():
    f = {**SAMPLE_FINDING, "severity": "CRITICAL"}
    sarif = review.findings_to_sarif([f], "owner/repo", "1")
    assert sarif["runs"][0]["tool"]["driver"]["rules"][0]["properties"]["security-severity"] == "9.5"

def test_findings_to_sarif_file_in_location():
    sarif = review.findings_to_sarif([SAMPLE_FINDING], "owner/repo", "1")
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "src/db.py"

def test_findings_to_sarif_line_in_location():
    sarif = review.findings_to_sarif([SAMPLE_FINDING], "owner/repo", "1")
    line = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
    assert line == 10

def test_findings_to_sarif_line_zero_clamped_to_one():
    f = {**SAMPLE_FINDING, "line": 0}
    sarif = review.findings_to_sarif([f], "owner/repo", "1")
    line = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"]
    assert line == 1

def test_findings_to_sarif_deduplicates_rules():
    findings = [SAMPLE_FINDING, {**SAMPLE_FINDING, "line": 20}]
    sarif = review.findings_to_sarif(findings, "owner/repo", "1")
    assert len(sarif["runs"][0]["tool"]["driver"]["rules"]) == 1
    assert len(sarif["runs"][0]["results"]) == 2

def test_findings_to_sarif_message_includes_description():
    sarif = review.findings_to_sarif([SAMPLE_FINDING], "owner/repo", "1")
    msg = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "SQL" in msg

def test_findings_to_sarif_tool_name():
    sarif = review.findings_to_sarif([SAMPLE_FINDING], "owner/repo", "1")
    assert sarif["runs"][0]["tool"]["driver"]["name"] == "Claude AI Reviewer"

def test_findings_to_sarif_pr_url_in_properties():
    sarif = review.findings_to_sarif([], "owner/repo", "99")
    assert "owner/repo" in sarif["runs"][0]["properties"]["pullRequest"]
    assert "99" in sarif["runs"][0]["properties"]["pullRequest"]


# --- parse_sarif_response ---

def test_parse_sarif_response_plain_json():
    data = {"findings": [], "summary": "ok"}
    result = review.parse_sarif_response(json.dumps(data))
    assert result == data

def test_parse_sarif_response_markdown_wrapped():
    data = {"findings": [], "summary": "ok"}
    wrapped = f"```json\n{json.dumps(data)}\n```"
    result = review.parse_sarif_response(wrapped)
    assert result == data

def test_parse_sarif_response_invalid_raises():
    with pytest.raises((json.JSONDecodeError, ValueError)):
        review.parse_sarif_response("not json at all")


# --- comment_has_findings ---

def test_comment_has_findings_high():
    assert review.comment_has_findings("There is a **HIGH** severity issue.") is True

def test_comment_has_findings_critical():
    assert review.comment_has_findings("**CRITICAL** vulnerability found.") is True

def test_comment_has_findings_none():
    assert review.comment_has_findings("No issues found. Looking good!") is False

def test_comment_has_findings_empty():
    assert review.comment_has_findings("") is False


# --- main: input validation ---

def test_main_missing_api_key(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_ANTHROPIC_API_KEY": ""}, clear=True):
        with pytest.raises(SystemExit) as exc:
            review.main()
    assert exc.value.code == 2
    assert "anthropic_api_key" in capsys.readouterr().err

def test_main_missing_token(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_GITHUB_TOKEN": ""}, clear=True):
        with pytest.raises(SystemExit) as exc:
            review.main()
    assert exc.value.code == 2
    assert "github_token" in capsys.readouterr().err

def test_main_missing_repo(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_REPO": ""}, clear=True):
        with pytest.raises(SystemExit) as exc:
            review.main()
    assert exc.value.code == 2
    assert "repo" in capsys.readouterr().err

def test_main_missing_pr_number(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_PR_NUMBER": ""}, clear=True):
        with pytest.raises(SystemExit) as exc:
            review.main()
    assert exc.value.code == 2
    assert "pr_number" in capsys.readouterr().err

def test_main_invalid_mode(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_MODE": "magic"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            review.main()
    assert exc.value.code == 2

def test_main_invalid_focus(capsys):
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_FOCUS": "vibes"}, clear=True):
        with pytest.raises(SystemExit) as exc:
            review.main()
    assert exc.value.code == 2


# --- main: execution ---

def test_main_empty_diff_exits_0(capsys):
    with patch.dict(os.environ, BASE_ENV, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value="   "):
            with pytest.raises(SystemExit) as exc:
                review.main()
    assert exc.value.code == 0
    assert "Nothing to review" in capsys.readouterr().out

def test_main_comment_mode_happy_path(capsys):
    with patch.dict(os.environ, BASE_ENV, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", return_value="## Summary\nLooks good."):
                with patch("ai_review.post_pr_comment") as mock_post:
                    with pytest.raises(SystemExit) as exc:
                        review.main()
    assert exc.value.code == 0
    mock_post.assert_called_once()

def test_main_comment_mode_posts_to_correct_pr():
    with patch.dict(os.environ, BASE_ENV, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", return_value="No issues."):
                with patch("ai_review.post_pr_comment") as mock_post:
                    with pytest.raises(SystemExit):
                        review.main()
    _, kwargs = mock_post.call_args
    args = mock_post.call_args[0]
    assert "owner/repo" in args
    assert "42" in args

def test_main_sarif_mode_writes_file(tmp_path):
    out = tmp_path / "out.sarif"
    env = {**BASE_ENV, "INPUT_MODE": "sarif", "INPUT_OUTPUT_FILE": str(out)}
    response = json.dumps({"findings": [SAMPLE_FINDING], "summary": "Found issues."})
    with patch.dict(os.environ, env, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", return_value=response):
                with pytest.raises(SystemExit) as exc:
                    review.main()
    assert exc.value.code == 0
    sarif = json.loads(out.read_text())
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"][0]["results"]) == 1

def test_main_sarif_mode_no_findings_exits_0(tmp_path):
    out = tmp_path / "out.sarif"
    env = {**BASE_ENV, "INPUT_MODE": "sarif", "INPUT_OUTPUT_FILE": str(out)}
    response = json.dumps({"findings": [], "summary": "All clear."})
    with patch.dict(os.environ, env, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", return_value=response):
                with pytest.raises(SystemExit) as exc:
                    review.main()
    assert exc.value.code == 0

def test_main_sarif_fail_on_findings_exits_1(tmp_path):
    out = tmp_path / "out.sarif"
    env = {**BASE_ENV, "INPUT_MODE": "sarif", "INPUT_OUTPUT_FILE": str(out), "INPUT_FAIL_ON_FINDINGS": "true"}
    response = json.dumps({"findings": [SAMPLE_FINDING], "summary": "Found issues."})
    with patch.dict(os.environ, env, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", return_value=response):
                with pytest.raises(SystemExit) as exc:
                    review.main()
    assert exc.value.code == 1

def test_main_sarif_fail_on_findings_no_findings_exits_0(tmp_path):
    out = tmp_path / "out.sarif"
    env = {**BASE_ENV, "INPUT_MODE": "sarif", "INPUT_OUTPUT_FILE": str(out), "INPUT_FAIL_ON_FINDINGS": "true"}
    response = json.dumps({"findings": [], "summary": "All clear."})
    with patch.dict(os.environ, env, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", return_value=response):
                with pytest.raises(SystemExit) as exc:
                    review.main()
    assert exc.value.code == 0

def test_main_comment_fail_on_findings_exits_1():
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_FAIL_ON_FINDINGS": "true"}, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", return_value="**HIGH** SQL injection found."):
                with patch("ai_review.post_pr_comment"):
                    with pytest.raises(SystemExit) as exc:
                        review.main()
    assert exc.value.code == 1

def test_main_comment_fail_on_findings_no_findings_exits_0():
    with patch.dict(os.environ, {**BASE_ENV, "INPUT_FAIL_ON_FINDINGS": "true"}, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", return_value="## Summary\nNo issues found."):
                with patch("ai_review.post_pr_comment"):
                    with pytest.raises(SystemExit) as exc:
                        review.main()
    assert exc.value.code == 0

def test_main_sarif_handles_markdown_wrapped_json(tmp_path):
    out = tmp_path / "out.sarif"
    env = {**BASE_ENV, "INPUT_MODE": "sarif", "INPUT_OUTPUT_FILE": str(out)}
    payload = {"findings": [SAMPLE_FINDING], "summary": "Found one issue."}
    wrapped = f"```json\n{json.dumps(payload)}\n```"
    with patch.dict(os.environ, env, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", return_value=wrapped):
                with pytest.raises(SystemExit) as exc:
                    review.main()
    assert exc.value.code == 0
    sarif = json.loads(out.read_text())
    assert len(sarif["runs"][0]["results"]) == 1

def test_main_sarif_invalid_json_exits_1(capsys):
    env = {**BASE_ENV, "INPUT_MODE": "sarif"}
    with patch.dict(os.environ, env, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", return_value="Sorry, I cannot help with that."):
                with pytest.raises(SystemExit) as exc:
                    review.main()
    assert exc.value.code == 1
    assert "valid JSON" in capsys.readouterr().err

def test_main_diff_truncated_prints_warning(capsys):
    big_diff = "+" + "x" * 50 + "\n"
    big_diff = big_diff * 4000
    with patch.dict(os.environ, BASE_ENV, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=big_diff):
            with patch("ai_review.call_claude", return_value="No issues."):
                with patch("ai_review.post_pr_comment"):
                    with pytest.raises(SystemExit):
                        review.main()
    assert "truncated" in capsys.readouterr().err

def test_main_fetch_error_exits_1(capsys):
    import urllib.error
    with patch.dict(os.environ, BASE_ENV, clear=True):
        with patch("ai_review.fetch_pr_diff", side_effect=urllib.error.HTTPError(None, 404, "Not Found", {}, None)):
            with pytest.raises(SystemExit) as exc:
                review.main()
    assert exc.value.code == 1

def test_main_claude_error_exits_1(capsys):
    with patch.dict(os.environ, BASE_ENV, clear=True):
        with patch("ai_review.fetch_pr_diff", return_value=SAMPLE_DIFF):
            with patch("ai_review.call_claude", side_effect=Exception("API error")):
                with pytest.raises(SystemExit) as exc:
                    review.main()
    assert exc.value.code == 1
    assert "Anthropic" in capsys.readouterr().err
