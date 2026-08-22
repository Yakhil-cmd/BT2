# Q4192: key collision after normalization - (API).ListCodespaces in api.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `ListCodespaces` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L369), letting the attacker's entry replace a trusted one?

## Target
- File/function: [internal/codespaces/api/api.go:369](internal/codespaces/api/api.go#L369) - `(API).ListCodespaces`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
