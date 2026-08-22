# Q4238: error body echoed verbatim - NewCAPIClient in client.go

## Question
Does the error construction in `NewCAPIClient` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L36) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:36](pkg/cmd/agent-task/capi/client.go#L36) - `NewCAPIClient`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
