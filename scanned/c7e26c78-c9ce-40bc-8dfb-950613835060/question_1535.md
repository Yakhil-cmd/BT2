# Q1535: world-readable secret material - (PathTraversalError).Error in absolute.go

## Question
Does `Error` in [internal/safepaths/absolute.go](internal/safepaths/absolute.go#L72) create a file that can contain a token or credential with permissive (0644/0666) mode or in a shared temp directory?

## Target
- File/function: [internal/safepaths/absolute.go:72](internal/safepaths/absolute.go#L72) - `(PathTraversalError).Error`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Read the created file from another account on a shared/multi-user host after the victim runs gh run download.
- Invariant to test: Anything that may hold credentials is created 0600 inside the user's private config dir.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test asserting the FileMode of the created file is 0600 and its parent is not a shared temp dir.
