# Q1511: error body echoed verbatim - NewCachedHTTPClient in http_client.go

## Question
Does the error construction in `NewCachedHTTPClient` in [api/http_client.go](api/http_client.go#L133) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [api/http_client.go:133](api/http_client.go#L133) - `NewCachedHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
