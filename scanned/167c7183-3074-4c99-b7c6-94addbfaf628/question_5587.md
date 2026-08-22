# Q5587: unvalidated devcontainer/config path - newSSHCommand in ssh.go

## Question
Can a repository-supplied config path flowing through `newSSHCommand` in [internal/codespaces/ssh.go](internal/codespaces/ssh.go#L65) select a local file to read or upload?

## Target
- File/function: [internal/codespaces/ssh.go:65](internal/codespaces/ssh.go#L65) - `newSSHCommand`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
