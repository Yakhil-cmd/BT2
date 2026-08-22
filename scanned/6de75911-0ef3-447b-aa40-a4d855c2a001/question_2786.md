# Q2786: unvalidated devcontainer/config path - firstConfiguredKeyPair in ssh.go

## Question
Can a repository-supplied config path flowing through `firstConfiguredKeyPair` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L472) select a local file to read or upload?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:472](pkg/cmd/codespace/ssh.go#L472) - `firstConfiguredKeyPair`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
