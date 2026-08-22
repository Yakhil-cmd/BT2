# Q0482: existing files overwritten silently - isWindowsReservedFilename in download.go

## Question
Does `isWindowsReservedFilename` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L456) overwrite files already present in the destination when the remote object dictates the name?

## Target
- File/function: [pkg/cmd/release/download/download.go:456](pkg/cmd/release/download/download.go#L456) - `isWindowsReservedFilename`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Name the asset after a file in the victim's working directory (Makefile, .env, a script).
- Invariant to test: Existing paths are never clobbered without an explicit flag.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test with a pre-existing file asserting an error.
