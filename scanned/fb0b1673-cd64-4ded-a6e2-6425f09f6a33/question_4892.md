# Q4892: unvalidated devcontainer/config path - AccessControlEntriesToVisibility in port_forwarder.go

## Question
Can a repository-supplied config path flowing through `AccessControlEntriesToVisibility` in [internal/codespaces/portforwarder/port_forwarder.go](internal/codespaces/portforwarder/port_forwarder.go#L362) select a local file to read or upload?

## Target
- File/function: [internal/codespaces/portforwarder/port_forwarder.go:362](internal/codespaces/portforwarder/port_forwarder.go#L362) - `AccessControlEntriesToVisibility`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish a repo whose devcontainer path field is a local absolute path.
- Invariant to test: Paths from repository data are validated as repo-relative.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test asserting rejection of absolute/traversal paths.
