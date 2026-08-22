# Q1359: logs rendered raw - keypairForPrivateKey in ssh.go

## Question
Does `keypairForPrivateKey` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L524) stream codespace-side logs to the terminal unsanitized?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:524](pkg/cmd/codespace/ssh.go#L524) - `keypairForPrivateKey`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Emit control sequences from inside the codespace.
- Invariant to test: Streamed remote output is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile log stream.
