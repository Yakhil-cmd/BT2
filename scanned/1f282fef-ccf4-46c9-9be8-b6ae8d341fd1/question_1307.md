# Q1307: codespace name used as a filesystem path - parseArgs in ssh.go

## Question
Can the codespace/display name reaching `parseArgs` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L153) become part of a local path (logs, keys, sockets) without sanitization?

## Target
- File/function: [internal/codespaces/ssh.go:153](internal/codespaces/ssh.go#L153) - `parseArgs`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Create a codespace whose name contains traversal characters.
- Invariant to test: Names are sanitized before path use.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved path stays confined.
