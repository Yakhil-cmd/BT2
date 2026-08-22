# Q5855: worktree/directory name from remote data - developRunCreate in develop.go

## Question
Does `developRunCreate` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L201) derive a filesystem path from a repo/branch/issue title that an unprivileged attacker chose?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:201](pkg/cmd/issue/develop/develop.go#L201) - `developRunCreate`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Create an issue/branch whose name contains traversal or a leading dash and let the victim run gh issue develop.
- Invariant to test: Derived directory names are sanitized and confined.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved directory stays under the expected parent.
