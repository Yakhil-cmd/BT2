# Q4883: unvalidated devcontainer/config path - (CodespaceConnection).Close in connection.go

## Question
Can a repository-supplied config path flowing through `Close` in [internal/codespaces/connection/connection.go](internal/codespaces/connection/connection.go#L111) select a local file to read or upload?

## Target
- File/function: [internal/codespaces/connection/connection.go:111](internal/codespaces/connection/connection.go#L111) - `(CodespaceConnection).Close`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
