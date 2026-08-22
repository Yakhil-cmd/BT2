# Q4169: codespace name used as a filesystem path - (CodespaceConnection).Connect in connection.go

## Question
Can the codespace/display name reaching `Connect` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L89) become part of a local path (logs, keys, sockets) without sanitization?

## Target
- File/function: [internal/codespaces/connection/connection.go:89](internal/codespaces/connection/connection.go#L89) - `(CodespaceConnection).Connect`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Create a codespace whose name contains traversal characters.
- Invariant to test: Names are sanitized before path use.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved path stays confined.
