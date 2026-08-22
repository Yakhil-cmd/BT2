# Q0660: error body echoed verbatim - (App).Jupyter in jupyter.go

## Question
Does the error construction in `Jupyter` in [pkg/cmd/codespace/jupyter.go](pkg/cmd/codespace/jupyter.go#L32) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/codespace/jupyter.go:32](pkg/cmd/codespace/jupyter.go#L32) - `(App).Jupyter`
- Entrypoint: gh codespace jupyter
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
