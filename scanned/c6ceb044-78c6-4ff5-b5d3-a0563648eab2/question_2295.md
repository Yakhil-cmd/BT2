# Q2295: key collision after normalization - (Client).AddRemote in client.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `AddRemote` in [git/client.go](git/client.go#L831), letting the attacker's entry replace a trusted one?

## Target
- File/function: [git/client.go:831](git/client.go#L831) - `(Client).AddRemote`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
