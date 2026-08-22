# Q1373: unvalidated devcontainer/config path - newJupyterCmd in jupyter.go

## Question
Can a repository-supplied config path flowing through `newJupyterCmd` in [pkg/cmd/codespace/jupyter.go](pkg/cmd/codespace/jupyter.go#L15) select a local file to read or upload?

## Target
- File/function: [pkg/cmd/codespace/jupyter.go:15](pkg/cmd/codespace/jupyter.go#L15) - `newJupyterCmd`
- Entrypoint: gh codespace jupyter
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
