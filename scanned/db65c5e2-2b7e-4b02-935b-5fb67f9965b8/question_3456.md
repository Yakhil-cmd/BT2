# Q3456: logs rendered raw - (CodespaceConnection).Close in connection.go

## Question
Does `Close` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L111) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [internal/codespaces/connection/connection.go:111](internal/codespaces/connection/connection.go#L111) - `(CodespaceConnection).Close`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
