# Q5620: error body echoed verbatim - (API).GetCodespace in api.go

## Question
Does the error construction in `GetCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L539) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [internal/codespaces/api/api.go:539](internal/codespaces/api/api.go#L539) - `(API).GetCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
