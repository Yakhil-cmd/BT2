# Q4107: deletion of attacker-chosen path - (IOStreams).TempFile in iostreams.go

## Question
Can an issue/PR title, body, comment, check output, or release note the attacker authored steer the cleanup/RemoveAll in `TempFile` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L459) at a path outside the directory gh created?

## Target
- File/function: [pkg/iostreams/iostreams.go:459](pkg/iostreams/iostreams.go#L459) - `(IOStreams).TempFile`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a name that resolves outside the install/download root so the cleanup deletes victim data.
- Invariant to test: Removal targets only paths gh itself created inside its own root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the removal path is validated with the same root check as writes.
