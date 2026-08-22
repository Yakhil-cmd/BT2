# Q1539: error body echoed verbatim - SmartBaseRepoFunc in default.go

## Question
Does the error construction in `SmartBaseRepoFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L152) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/factory/default.go:152](pkg/cmd/factory/default.go#L152) - `SmartBaseRepoFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
