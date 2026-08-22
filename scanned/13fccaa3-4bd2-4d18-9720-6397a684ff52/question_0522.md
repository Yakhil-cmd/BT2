# Q0522: key collision after normalization - createGist in create.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `createGist` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L263), letting the attacker's entry replace a trusted one?

## Target
- File/function: [pkg/cmd/gist/create/create.go:263](pkg/cmd/gist/create/create.go#L263) - `createGist`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
