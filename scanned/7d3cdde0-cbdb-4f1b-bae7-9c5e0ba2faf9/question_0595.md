# Q0595: unvalidated devcontainer/config path - GetCodespaceConnection in codespaces.go

## Question
Can a repository-supplied config path flowing through `GetCodespaceConnection` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L60) select a local file to read or upload?

## Target
- File/function: [internal/codespaces/codespaces.go:60](internal/codespaces/codespaces.go#L60) - `GetCodespaceConnection`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
