# Q1372: unvalidated devcontainer/config path - (App).VSCode in code.go

## Question
Can a repository-supplied config path flowing through `VSCode` in [pkg/cmd/codespace/code.go](pkg/cmd/codespace/code.go#L36) select a local file to read or upload?

## Target
- File/function: [pkg/cmd/codespace/code.go:36](pkg/cmd/codespace/code.go#L36) - `(App).VSCode`
- Entrypoint: gh codespace code
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
