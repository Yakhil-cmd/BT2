# Q0618: codespace name used as a filesystem path - isJupyterServerURLValid in invoker.go

## Question
Can the codespace/display name reaching `isJupyterServerURLValid` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L321) become part of a local path (logs, keys, sockets) without sanitization?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:321](internal/codespaces/rpc/invoker.go#L321) - `isJupyterServerURLValid`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Create a codespace whose name contains traversal characters.
- Invariant to test: Names are sanitized before path use.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved path stays confined.
