# sarif-validator

Validate a SARIF file before uploading to GitHub code scanning. Catches schema errors, missing required fields, malformed rules, and common gotchas that cause silent upload failures or misleading results in the GitHub UI.

## Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `sarif_file` | Yes | — | Path to the SARIF file to validate |
| `strict` | No | `false` | Fail on warnings as well as errors |
| `max_results` | No | — | Warn if result count exceeds this threshold |

## Checks

| Check | Failure Mode |
|---|---|
| Valid JSON | error |
| SARIF version present and = `2.1.0` | error |
| Required top-level fields (`version`, `runs`) | error |
| `tool.driver.name` present in each run | error |
| No duplicate `ruleId`s in rules array | error |
| All result `ruleId`s reference a known rule | error |
| All results have a location with URI and `startLine` | warning |
| No absolute URI paths (won't resolve in GitHub UI) | warning |
| All `level` values are valid (`error`, `warning`, `note`, `none`) | error |
| Result count ≤ `max_results` (if set) | warning |

## Usage

### Validate before upload

```yaml
- name: Validate SARIF
  uses: cschooley/ghas-actions/actions/sarif-validator@main
  with:
    sarif_file: results.sarif

- name: Upload to GitHub code scanning
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Strict mode with result cap

```yaml
- uses: cschooley/ghas-actions/actions/sarif-validator@main
  with:
    sarif_file: results.sarif
    strict: true
    max_results: 500
```

See [examples/validate-before-upload.yml](examples/validate-before-upload.yml) for a full workflow.

## Output

```
SARIF Validation: results.sarif
------------------------------------------------------------
[PASS] Valid JSON
[PASS] Schema version: 2.1.0
[PASS] 'runs' present (1 run(s))
[PASS] Run 1: tool.driver.name = 'CodeQL'
[PASS] Run 1: no duplicate ruleIds (42 rule(s))
[PASS] Run 1: all result ruleIds reference known rules
[PASS] Run 1: all results have valid locations
[PASS] Run 1: URI patterns look sane
[PASS] Run 1: all level values are valid
------------------------------------------------------------
Summary: 156 result(s), 42 unique rule(s)

Result: PASS
```

## Trigger / Cost

This action runs in milliseconds — it reads a local file and does no network calls. Add it before every `upload-sarif` step regardless of trigger. There is no cost reason to skip it.

```yaml
on:
  pull_request:
  push:
    branches: [main]
```

See [docs/workflow-triggers.md](../../docs/workflow-triggers.md) for broader trigger strategy guidance.

## Known Limitations

- Does not validate against the full JSON Schema for SARIF 2.1.0 — checks are targeted at the fields GitHub code scanning actually uses
- `level` at the `rule.defaultConfiguration` level is not checked, only result-level `level`
