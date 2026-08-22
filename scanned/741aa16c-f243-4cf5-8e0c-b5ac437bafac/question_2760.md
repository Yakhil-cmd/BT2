# Q2760: unvalidated devcontainer/config path - isJupyterServerURLValid in invoker.go

## Question
Can a repository-supplied config path flowing through `isJupyterServerURLValid` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L321) select a local file to read or upload?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:321](internal/codespaces/rpc/invoker.go#L321) - `isJupyterServerURLValid`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
