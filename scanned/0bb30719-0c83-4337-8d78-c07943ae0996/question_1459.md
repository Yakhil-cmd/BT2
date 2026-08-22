# Q1459: deletion of attacker-chosen path - HomeDirPath in config.go

## Question
Can a hostname, OAuth/device response, or git credential-protocol input the attacker supplies steer the cleanup/RemoveAll in `HomeDirPath` in [internal/config/config.go](internal/config/config.go#L702) at a path outside the directory gh created?

## Target
- File/function: [internal/config/config.go:702](internal/config/config.go#L702) - `HomeDirPath`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish a name that resolves outside the install/download root so the cleanup deletes victim data.
- Invariant to test: Removal targets only paths gh itself created inside its own root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the removal path is validated with the same root check as writes.
