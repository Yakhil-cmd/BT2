# Q1515: empty/default host fallback - (telemetryDisablerTransport).RoundTrip in http_client.go

## Question
When host resolution fails inside `RoundTrip` in [api/http_client.go](api/http_client.go#L209), does it silently fall back to the default host (or the first configured account) and use those credentials for attacker-chosen coordinates?

## Target
- File/function: [api/http_client.go:209](api/http_client.go#L209) - `(telemetryDisablerTransport).RoundTrip`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Make host resolution fail on an attacker-published repo and observe which token is used.
- Invariant to test: Failed resolution aborts; no implicit credential selection.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with an unresolvable host asserting an error rather than a default token.
