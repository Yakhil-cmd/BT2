# Q5658: unvalidated devcontainer/config path - (App).RunWithProgress in common.go

## Question
Can a repository-supplied config path flowing through `RunWithProgress` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L63) select a local file to read or upload?

## Target
- File/function: [pkg/cmd/codespace/common.go:63](pkg/cmd/codespace/common.go#L63) - `(App).RunWithProgress`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
