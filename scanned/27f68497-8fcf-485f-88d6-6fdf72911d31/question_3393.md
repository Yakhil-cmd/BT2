# Q3393: world-readable secret material - (IOStreams).TempFile in iostreams.go

## Question
Does `TempFile` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L459) create a file that can contain a token or credential with permissive (0644/0666) mode or in a shared temp directory?

## Target
- File/function: [pkg/iostreams/iostreams.go:459](pkg/iostreams/iostreams.go#L459) - `(IOStreams).TempFile`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Read the created file from another account on a shared/multi-user host after the victim runs gh pr view.
- Invariant to test: Anything that may hold credentials is created 0600 inside the user's private config dir.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Unit test asserting the FileMode of the created file is 0600 and its parent is not a shared temp dir.
