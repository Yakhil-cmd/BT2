# Q4879: logs rendered raw - waitUntilCodespaceConnectionReady in codespaces.go

## Question
Does `waitUntilCodespaceConnectionReady` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L78) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [internal/codespaces/codespaces.go:78](internal/codespaces/codespaces.go#L78) - `waitUntilCodespaceConnectionReady`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
