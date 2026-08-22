# Q4763: deletion of attacker-chosen path - (destinationWriter).makePath in download.go

## Question
Can an asset, artifact, gist, or archive-member name and its bytes steer the cleanup/RemoveAll in `makePath` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L379) at a path outside the directory gh created?

## Target
- File/function: [pkg/cmd/release/download/download.go:379](pkg/cmd/release/download/download.go#L379) - `(destinationWriter).makePath`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a name that resolves outside the install/download root so the cleanup deletes victim data.
- Invariant to test: Removal targets only paths gh itself created inside its own root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting the removal path is validated with the same root check as writes.
