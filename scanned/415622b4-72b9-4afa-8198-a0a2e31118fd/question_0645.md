# Q0645: codespace name used as a filesystem path - keypairForPrivateKey in ssh.go

## Question
Can the codespace/display name reaching `keypairForPrivateKey` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L524) become part of a local path (logs, keys, sockets) without sanitization?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:524](pkg/cmd/codespace/ssh.go#L524) - `keypairForPrivateKey`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Create a codespace whose name contains traversal characters.
- Invariant to test: Names are sanitized before path use.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved path stays confined.
