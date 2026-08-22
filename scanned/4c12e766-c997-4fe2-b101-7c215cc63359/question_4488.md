# Q4488: worktree/directory name from remote data - isEqualSet in finder.go

## Question
Does `isEqualSet` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L673) derive a filesystem path from a repo/branch/issue title that an unprivileged attacker chose?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:673](pkg/cmd/pr/shared/finder.go#L673) - `isEqualSet`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Create an issue/branch whose name contains traversal or a leading dash and let the victim run gh pr.
- Invariant to test: Derived directory names are sanitized and confined.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved directory stays under the expected parent.
