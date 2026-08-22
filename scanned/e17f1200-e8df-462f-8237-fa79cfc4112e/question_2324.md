# Q2324: checkout of attacker-controlled path or worktree - setDefaultRun in setdefault.go

## Question
Can a branch/PR name reaching `setDefaultRun` in [pkg/cmd/repo/setdefault/setdefault.go](pkg/cmd/repo/setdefault/setdefault.go#L126) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [pkg/cmd/repo/setdefault/setdefault.go:126](pkg/cmd/repo/setdefault/setdefault.go#L126) - `setDefaultRun`
- Entrypoint: gh repo setdefault
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
