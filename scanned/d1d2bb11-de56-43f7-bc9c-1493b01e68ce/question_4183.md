# Q4183: unvalidated devcontainer/config path - (invoker).StartJupyterServer in invoker.go

## Question
Can a repository-supplied config path flowing through `StartJupyterServer` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L169) select a local file to read or upload?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:169](internal/codespaces/rpc/invoker.go#L169) - `(invoker).StartJupyterServer`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
