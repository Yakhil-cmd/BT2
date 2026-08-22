# Q5816: worktree/directory name from remote data - (Command).setRepoDir in command.go

## Question
Does `setRepoDir` in [git/command.go](git/command.go#L67) derive a filesystem path from a repo/branch/issue title that an unprivileged attacker chose?

## Target
- File/function: [git/command.go:67](git/command.go#L67) - `(Command).setRepoDir`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Create an issue/branch whose name contains traversal or a leading dash and let the victim run gh repo clone.
- Invariant to test: Derived directory names are sanitized and confined.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved directory stays under the expected parent.
