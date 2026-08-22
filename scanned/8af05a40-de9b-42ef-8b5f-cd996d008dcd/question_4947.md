# Q4947: codespace name used as a filesystem path - (codespace).displayName in common.go

## Question
Can the codespace/display name reaching `displayName` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L194) become part of a local path (logs, keys, sockets) without sanitization?

## Target
- File/function: [pkg/cmd/codespace/common.go:194](pkg/cmd/codespace/common.go#L194) - `(codespace).displayName`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Create a codespace whose name contains traversal characters.
- Invariant to test: Names are sanitized before path use.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved path stays confined.
