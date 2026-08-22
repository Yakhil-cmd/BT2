# Q1604: worktree/directory name from remote data - NewCmdSync in sync.go

## Question
Does `NewCmdSync` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L36) derive a filesystem path from a repo/branch/issue title that an unprivileged attacker chose?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:36](pkg/cmd/repo/sync/sync.go#L36) - `NewCmdSync`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Create an issue/branch whose name contains traversal or a leading dash and let the victim run gh repo sync.
- Invariant to test: Derived directory names are sanitized and confined.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved directory stays under the expected parent.
