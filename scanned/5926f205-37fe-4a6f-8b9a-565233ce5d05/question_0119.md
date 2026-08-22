# Q0119: checkout of attacker-controlled path or worktree - branchFunc in default.go

## Question
Can a branch/PR name reaching `branchFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L262) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [pkg/cmd/factory/default.go:262](pkg/cmd/factory/default.go#L262) - `branchFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
