# Q5826: checkout of attacker-controlled path or worktree - syncLocalRepo in sync.go

## Question
Can a branch/PR name reaching `syncLocalRepo` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L99) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:99](pkg/cmd/repo/sync/sync.go#L99) - `syncLocalRepo`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
