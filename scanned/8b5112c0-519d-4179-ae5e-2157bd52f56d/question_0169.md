# Q0169: worktree/directory name from remote data - simplifyURL in clone.go

## Question
Does `simplifyURL` in [pkg/cmd/repo/clone/clone.go](pkg/cmd/repo/clone/clone.go#L249) derive a filesystem path from a repo/branch/issue title that an unprivileged attacker chose?

## Target
- File/function: [pkg/cmd/repo/clone/clone.go:249](pkg/cmd/repo/clone/clone.go#L249) - `simplifyURL`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Create an issue/branch whose name contains traversal or a leading dash and let the victim run gh repo clone.
- Invariant to test: Derived directory names are sanitized and confined.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test asserting the resolved directory stays under the expected parent.
