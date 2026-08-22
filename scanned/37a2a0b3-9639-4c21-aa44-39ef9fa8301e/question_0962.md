# Q0962: key collision after normalization - (Extension).loadManifest in extension.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `loadManifest` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L224), letting the attacker's entry replace a trusted one?

## Target
- File/function: [pkg/cmd/extension/extension.go:224](pkg/cmd/extension/extension.go#L224) - `(Extension).loadManifest`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
