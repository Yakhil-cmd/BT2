# Q5189: path traversal in join - resolveWorktreeTarget in worktree.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes reaching `resolveWorktreeTarget` in [pkg/cmd/pr/shared/worktree.go](pkg/cmd/pr/shared/worktree.go#L62) contain `../` or an absolute path so the `filepath.Join` target escapes the intended output directory?

## Target
- File/function: [pkg/cmd/pr/shared/worktree.go:62](pkg/cmd/pr/shared/worktree.go#L62) - `resolveWorktreeTarget`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish an entry named `../../.bashrc` (or `..\..\` on Windows) and let the victim run gh pr.
- Invariant to test: Every written path must remain inside the chosen root after Clean and Abs.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Fuzz the name with traversal, absolute, drive-letter, and UNC forms; assert the resolved path is prefixed by the root.
