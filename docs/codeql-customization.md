# CodeQL Customization Guide

## Query Suites

GitHub ships three built-in suites, each a superset of the previous:

| Suite | Flag | Use case |
|---|---|---|
| `default` | *(omit `queries:`)* | Standard precision/recall balance, recommended for most repos |
| `security-extended` | `queries: security-extended` | Broader coverage, some lower-confidence results |
| `security-and-quality` | `queries: security-and-quality` | Everything above + code quality rules |

To use a suite in your workflow:

```yaml
- uses: github/codeql-action/init@v3
  with:
    languages: javascript-typescript
    queries: security-extended
```

## Adding Custom Queries

Place `.ql` files under `codeql-queries/` and reference them in the workflow config block:

```yaml
- uses: github/codeql-action/init@v3
  with:
    config: |
      queries:
        - uses: ./codeql-queries
```

### Writing a Custom Query (JavaScript example)

```ql
/**
 * @name Hardcoded password in string literal
 * @description Detects string assignments to variables named 'password'
 * @kind problem
 * @problem.severity error
 * @security-severity 9.0
 * @id js/hardcoded-password
 * @tags security
 */

import javascript

from AssignExpr assign, StringLiteral str
where
  assign.getLhs().(VarAccess).getName().toLowerCase() = "password" and
  assign.getRhs() = str and
  str.getStringValue().length() > 0
select assign, "Hardcoded password assigned here."
```

## Filtering Results

To suppress a false positive inline:

```javascript
// lgtm[js/hardcoded-password]
const password = process.env.PASSWORD; // safe — not actually hardcoded
```

Or add a path filter in the workflow config:

```yaml
config: |
  paths-ignore:
    - "**/*.test.js"
    - "test/"
    - "fixtures/"
```

## Interpreting Alerts

- **Error / Critical** — Fix before merge. These are high-confidence, high-severity.
- **Warning** — Review and triage. May be true positives in sensitive contexts.
- **Note / Recommendation** — Code quality. Fix in a follow-up, not blocking.
