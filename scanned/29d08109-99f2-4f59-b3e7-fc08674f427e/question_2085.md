# Q2085: unvalidated devcontainer/config path - newCodeCmd in code.go

## Question
Can a repository-supplied config path flowing through `newCodeCmd` in [pkg/cmd/codespace/code.go](pkg/cmd/codespace/code.go#L11) select a local file to read or upload?

## Target
- File/function: [pkg/cmd/codespace/code.go:11](pkg/cmd/codespace/code.go#L11) - `newCodeCmd`
- Entrypoint: gh codespace code
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
