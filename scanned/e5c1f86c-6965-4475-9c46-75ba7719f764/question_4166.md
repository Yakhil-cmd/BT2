# Q4166: codespace name used as a filesystem path - waitUntilCodespaceConnectionReady in codespaces.go

## Question
Can the codespace/display name reaching `waitUntilCodespaceConnectionReady` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L78) become part of a local path (logs, keys, sockets) without sanitization?

## Target
- File/function: [internal/codespaces/codespaces.go:78](internal/codespaces/codespaces.go#L78) - `waitUntilCodespaceConnectionReady`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Create a codespace whose name contains traversal characters.
- Invariant to test: Names are sanitized before path use.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved path stays confined.
