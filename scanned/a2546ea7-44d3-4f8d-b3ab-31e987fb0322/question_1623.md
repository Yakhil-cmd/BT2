# Q1623: key collision after normalization - (finder).Find in finder.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `Find` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L111), letting the attacker's entry replace a trusted one?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:111](pkg/cmd/pr/shared/finder.go#L111) - `(finder).Find`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
