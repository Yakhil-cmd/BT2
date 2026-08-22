# Q3497: logs rendered raw - selectSSHKeys in ssh.go

## Question
Does `selectSSHKeys` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L323) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:323](pkg/cmd/codespace/ssh.go#L323) - `selectSSHKeys`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
