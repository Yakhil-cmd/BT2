# Q4426: worktree/directory name from remote data - parseWorktrees in client.go

## Question
Does `parseWorktrees` in [git/client.go](git/client.go#L294) derive a filesystem path from a repo/branch/issue title that an unprivileged attacker chose?

## Target
- File/function: [git/client.go:294](git/client.go#L294) - `parseWorktrees`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Create an issue/branch whose name contains traversal or a leading dash and let the victim run gh repo clone.
- Invariant to test: Derived directory names are sanitized and confined.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved directory stays under the expected parent.
