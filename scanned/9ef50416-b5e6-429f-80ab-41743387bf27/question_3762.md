# Q3762: submodule/recursive flag propagation - resolveWorktreeTarget in worktree.go

## Question
Does `resolveWorktreeTarget` in [pkg/cmd/pr/shared/worktree.go](pkg/cmd/pr/shared/worktree.go#L62) add recursive submodule handling to a git invocation on attacker-published repositories, expanding the attack surface to arbitrary URLs in `.gitmodules`?

## Target
- File/function: [pkg/cmd/pr/shared/worktree.go:62](pkg/cmd/pr/shared/worktree.go#L62) - `resolveWorktreeTarget`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo with hostile submodule URLs.
- Invariant to test: Recursive operations are opt-in and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the argv does not enable recursion by default.
