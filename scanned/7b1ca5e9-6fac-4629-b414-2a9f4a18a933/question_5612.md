# Q5612: unvalidated devcontainer/config path - (invoker).heartbeat in invoker.go

## Question
Can a repository-supplied config path flowing through `heartbeat` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L277) select a local file to read or upload?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:277](internal/codespaces/rpc/invoker.go#L277) - `(invoker).heartbeat`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
