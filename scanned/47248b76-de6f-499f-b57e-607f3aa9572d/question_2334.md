# Q2334: sync/push targets attacker remote - resolveWorktreeTarget in worktree.go

## Question
Can `resolveWorktreeTarget` in [pkg/cmd/pr/shared/worktree.go](pkg/cmd/pr/shared/worktree.go#L62) be steered by repo metadata into pushing the victim's local branches (possibly containing private code) to a remote the attacker controls?

## Target
- File/function: [pkg/cmd/pr/shared/worktree.go:62](pkg/cmd/pr/shared/worktree.go#L62) - `resolveWorktreeTarget`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo whose upstream/parent metadata points at the attacker.
- Invariant to test: Push targets are confirmed and host-validated.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the push remote for hostile metadata.
