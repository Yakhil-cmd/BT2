# Q2617: symlink member - NewCmdDownload in download.go

## Question
Does extraction in `NewCmdDownload` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L46) honour a member with a symlink mode bit, letting a later member write through it to an arbitrary location?

## Target
- File/function: [pkg/cmd/release/download/download.go:46](pkg/cmd/release/download/download.go#L46) - `NewCmdDownload`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Two-entry archive: `link -> ~/.ssh`, then `link/authorized_keys`.
- Invariant to test: Non-regular archive members (symlink, device, hardlink) are skipped or rejected.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with a symlink-mode entry asserting it is not created.
