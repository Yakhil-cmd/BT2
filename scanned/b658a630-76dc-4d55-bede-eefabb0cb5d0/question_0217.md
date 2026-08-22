# Q0217: world-readable secret material - NewManager in manager.go

## Question
Does `NewManager` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L59) create a file that can contain a token or credential with permissive (0644/0666) mode or in a shared temp directory?

## Target
- File/function: [pkg/cmd/extension/manager.go:59](pkg/cmd/extension/manager.go#L59) - `NewManager`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Read the created file from another account on a shared/multi-user host after the victim runs gh extension manager.
- Invariant to test: Anything that may hold credentials is created 0600 inside the user's private config dir.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test asserting the FileMode of the created file is 0600 and its parent is not a shared temp dir.
