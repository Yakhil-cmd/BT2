# Q5840: symlink not resolved before write - resolveWorktreeTarget in worktree.go

## Question
Does `resolveWorktreeTarget` in [pkg/cmd/pr/shared/worktree.go](pkg/cmd/pr/shared/worktree.go#L62) write through a path component that may already be a symlink created earlier by the same attacker-controlled payload?

## Target
- File/function: [pkg/cmd/pr/shared/worktree.go:62](pkg/cmd/pr/shared/worktree.go#L62) - `resolveWorktreeTarget`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Have the payload create `dir -> /home/victim/.ssh` first, then a file under `dir/`.
- Invariant to test: Writes resolve symlinks and reject any component leaving the root (O_NOFOLLOW semantics).
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Integration test extracting a two-entry payload (symlink then file) and asserting the outside target is untouched.
