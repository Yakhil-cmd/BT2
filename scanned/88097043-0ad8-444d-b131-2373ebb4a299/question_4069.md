# Q4069: existing files overwritten silently - NewCmdReadFile in read_file.go

## Question
Does `NewCmdReadFile` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L51) overwrite files already present in the destination when the remote object dictates the name?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:51](pkg/cmd/repo/read-file/read_file.go#L51) - `NewCmdReadFile`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Name the asset after a file in the victim's working directory (Makefile, .env, a script).
- Invariant to test: Existing paths are never clobbered without an explicit flag.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with a pre-existing file asserting an error.
