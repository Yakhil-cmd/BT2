# Q4050: world-readable secret material - (destinationWriter).makePath in download.go

## Question
Does `makePath` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L379) create a file that can contain a token or credential with permissive (0644/0666) mode or in a shared temp directory?

## Target
- File/function: [pkg/cmd/release/download/download.go:379](pkg/cmd/release/download/download.go#L379) - `(destinationWriter).makePath`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Read the created file from another account on a shared/multi-user host after the victim runs gh release download.
- Invariant to test: Anything that may hold credentials is created 0600 inside the user's private config dir.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test asserting the FileMode of the created file is 0600 and its parent is not a shared temp dir.
