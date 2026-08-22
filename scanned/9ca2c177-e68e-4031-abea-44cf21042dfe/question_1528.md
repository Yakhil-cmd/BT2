# Q1528: key collision after normalization - FromFullNameWithHost in repo.go

## Question
Can two remote keys that differ only in case/normalization collide in the map built by `FromFullNameWithHost` in [internal/ghrepo/repo.go](internal/ghrepo/repo.go#L52), letting the attacker's entry replace a trusted one?

## Target
- File/function: [internal/ghrepo/repo.go:52](internal/ghrepo/repo.go#L52) - `FromFullNameWithHost`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish two entries whose names normalize identically.
- Invariant to test: Collisions are detected and rejected rather than last-write-wins.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Unit test with colliding keys asserting an error.
