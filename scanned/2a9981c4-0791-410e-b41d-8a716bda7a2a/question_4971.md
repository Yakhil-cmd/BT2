# Q4971: world-readable secret material - extractTarGz in copilot.go

## Question
Does `extractTarGz` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L413) create a file that can contain a token or credential with permissive (0644/0666) mode or in a shared temp directory?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:413](pkg/cmd/copilot/copilot.go#L413) - `extractTarGz`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Read the created file from another account on a shared/multi-user host after the victim runs gh copilot copilot.
- Invariant to test: Anything that may hold credentials is created 0600 inside the user's private config dir.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test asserting the FileMode of the created file is 0600 and its parent is not a shared temp dir.
