# Q3820: checkout of attacker-controlled path or worktree - (gitExecuter).Clone in git.go

## Question
Can a branch/PR name reaching `Clone` in [pkg/cmd/extension/git.go](pkg/cmd/extension/git.go#L28) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [pkg/cmd/extension/git.go:28](pkg/cmd/extension/git.go#L28) - `(gitExecuter).Clone`
- Entrypoint: gh extension git
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
