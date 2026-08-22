# Q2045: key collision after normalization - isUsernameValid in invoker.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `isUsernameValid` in [internal/codespaces/rpc/invoker.go](internal/codespaces/rpc/invoker.go#L313), letting the attacker's entry replace a trusted one?

## Target
- File/function: [internal/codespaces/rpc/invoker.go:313](internal/codespaces/rpc/invoker.go#L313) - `isUsernameValid`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
