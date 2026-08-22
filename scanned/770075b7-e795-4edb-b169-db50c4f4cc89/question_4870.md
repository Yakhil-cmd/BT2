# Q4870: checkout of attacker-controlled path or worktree - (remoteGitClient).LastCommit in browse.go

## Question
Can a branch/PR name reaching `LastCommit` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L375) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [pkg/cmd/browse/browse.go:375](pkg/cmd/browse/browse.go#L375) - `(remoteGitClient).LastCommit`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
