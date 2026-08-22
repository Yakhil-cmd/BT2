# Q0472: duplicate entry overwrite - fetchReleasePath in fetch.go

## Question
Can duplicate member names in an archive processed by `fetchReleasePath` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L281) let a second entry silently replace an already-validated first entry?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:281](pkg/cmd/release/shared/fetch.go#L281) - `fetchReleasePath`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an archive where the same path appears twice with different content.
- Invariant to test: Duplicate member names are rejected before any write.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with a duplicated entry asserting an error.
