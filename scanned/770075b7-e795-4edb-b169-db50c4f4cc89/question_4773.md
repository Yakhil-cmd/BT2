# Q4773: symlink member - newZipLogMap in logs.go

## Question
Does extraction in `newZipLogMap` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L166) honour a member with a symlink mode bit, letting a later member write through it to an arbitrary location?

## Target
- File/function: [pkg/cmd/run/view/logs.go:166](pkg/cmd/run/view/logs.go#L166) - `newZipLogMap`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Two-entry archive: `link -> ~/.ssh`, then `link/authorized_keys`.
- Invariant to test: Non-regular archive members (symlink, device, hardlink) are skipped or rejected.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with a symlink-mode entry asserting it is not created.
