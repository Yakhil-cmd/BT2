# Q4212: logs rendered raw - automaticSSHKeyPair in ssh.go

## Question
Does `automaticSSHKeyPair` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L383) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:383](pkg/cmd/codespace/ssh.go#L383) - `automaticSSHKeyPair`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
