# Q0526: key collision after normalization - (Untrusted).UnmarshalJSON in untrusted.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `UnmarshalJSON` in [pkg/iostreams/untrusted.go](pkg/iostreams/untrusted.go#L63), letting the attacker's entry replace a trusted one?

## Target
- File/function: [pkg/iostreams/untrusted.go:63](pkg/iostreams/untrusted.go#L63) - `(Untrusted).UnmarshalJSON`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
