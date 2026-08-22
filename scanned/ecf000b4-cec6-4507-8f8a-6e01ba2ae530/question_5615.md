# Q5615: logs rendered raw - New in api.go

## Question
Does `New` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L72) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [internal/codespaces/api/api.go:72](internal/codespaces/api/api.go#L72) - `New`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
