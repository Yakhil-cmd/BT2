# Q5647: unvalidated devcontainer/config path - getDevContainer in ports.go

## Question
Can a repository-supplied config path flowing through `getDevContainer` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L188) select a local file to read or upload?

## Target
- File/function: [pkg/cmd/codespace/ports.go:188](pkg/cmd/codespace/ports.go#L188) - `getDevContainer`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
