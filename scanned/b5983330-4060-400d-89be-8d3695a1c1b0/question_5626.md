# Q5626: codespace name used as a filesystem path - (API).GetCodespaceBillableOwner in api.go

## Question
Can the codespace/display name reaching `GetCodespaceBillableOwner` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L828) become part of a local path (logs, keys, sockets) without sanitization?

## Target
- File/function: [internal/codespaces/api/api.go:828](internal/codespaces/api/api.go#L828) - `(API).GetCodespaceBillableOwner`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Create a codespace whose name contains traversal characters.
- Invariant to test: Names are sanitized before path use.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved path stays confined.
