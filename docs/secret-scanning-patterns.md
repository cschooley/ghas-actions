# Secret Scanning Custom Patterns

GitHub Secret Scanning automatically detects 200+ partner token types. Custom patterns let you catch internal secrets.

## Configuring Custom Patterns

Navigate to: **Settings → Security → Secret scanning → Custom patterns → New pattern**

## Recommended Patterns

### Internal API Keys

```
(?i)(internal[_-]?api[_-]?key|int[_-]?api)["\'\s:=]+([a-z0-9]{32,64})
```

Test string: `internal_api_key="abc123def456abc123def456abc123de"`

### Database Connection Strings

```
(?i)(mongodb|postgres|mysql|redis|amqp):\/\/[^:]+:[^@]+@[^\s"']+
```

Test string: `mongodb://admin:s3cr3t@db.internal:27017/prod`

### Generic High-Entropy Secrets

```
(?i)(secret|password|passwd|pwd|token|apikey|api_key)["\'\s:=]+"([A-Za-z0-9+/]{40,}={0,2})"
```

## Push Protection

When push protection is enabled, GitHub blocks pushes containing detected secrets. Developers can:

1. Remove the secret and push clean code
2. Request a bypass (creates an audit log entry)

Enable via: **Settings → Security → Secret scanning → Push protection → Enable**

## Excluding Paths

Some paths should be excluded from scanning (e.g., test fixtures with fake secrets):

```yaml
# .github/secret_scanning.yml
paths-ignore:
  - "test/fixtures/**"
  - "**/*.example"
```

## Responding to Alerts

1. **Revoke** the exposed credential immediately — assume it's compromised
2. **Rotate** to a new secret
3. **Audit** access logs for the credential during the exposure window
4. **Close** the alert after rotation with a resolution note
