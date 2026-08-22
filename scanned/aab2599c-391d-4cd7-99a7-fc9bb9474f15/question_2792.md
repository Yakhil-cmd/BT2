# Q2792: codespace name used as a filesystem path - (App).ListPorts in ports.go

## Question
Can the codespace/display name reaching `ListPorts` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L53) become part of a local path (logs, keys, sockets) without sanitization?

## Target
- File/function: [pkg/cmd/codespace/ports.go:53](pkg/cmd/codespace/ports.go#L53) - `(App).ListPorts`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Create a codespace whose name contains traversal characters.
- Invariant to test: Names are sanitized before path use.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved path stays confined.
