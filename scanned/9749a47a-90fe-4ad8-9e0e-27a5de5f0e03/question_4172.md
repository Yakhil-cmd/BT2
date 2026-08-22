# Q4172: unvalidated devcontainer/config path - getTunnelClient in connection.go

## Question
Can a repository-supplied config path flowing through `getTunnelClient` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L152) select a local file to read or upload?

## Target
- File/function: [internal/codespaces/connection/connection.go:152](internal/codespaces/connection/connection.go#L152) - `getTunnelClient`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
