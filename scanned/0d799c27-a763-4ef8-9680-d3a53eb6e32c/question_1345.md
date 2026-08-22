# Q1345: unvalidated devcontainer/config path - (API).CreateCodespace in api.go

## Question
Can a repository-supplied config path flowing through `CreateCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L895) select a local file to read or upload?

## Target
- File/function: [internal/codespaces/api/api.go:895](internal/codespaces/api/api.go#L895) - `(API).CreateCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
