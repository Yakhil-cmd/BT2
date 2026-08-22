# Q2021: logs rendered raw - parseArgs in ssh.go

## Question
Does `parseArgs` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L153) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [internal/codespaces/ssh.go:153](internal/codespaces/ssh.go#L153) - `parseArgs`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
