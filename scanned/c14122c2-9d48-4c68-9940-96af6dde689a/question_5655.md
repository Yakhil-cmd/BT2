# Q5655: error body echoed verbatim - newJupyterCmd in jupyter.go

## Question
Does the error construction in `newJupyterCmd` in [pkg/cmd/codespace/jupyter.go](pkg/cmd/codespace/jupyter.go#L15) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/codespace/jupyter.go:15](pkg/cmd/codespace/jupyter.go#L15) - `newJupyterCmd`
- Entrypoint: gh codespace jupyter
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
