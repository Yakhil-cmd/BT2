# Q2077: error body echoed verbatim - newPortsCmd in ports.go

## Question
Does the error construction in `newPortsCmd` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L27) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/codespace/ports.go:27](pkg/cmd/codespace/ports.go#L27) - `newPortsCmd`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
