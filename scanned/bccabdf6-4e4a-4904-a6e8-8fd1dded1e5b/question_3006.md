# Q3006: checkout of attacker-controlled path or worktree - ParseRemoteTrackingRef in client.go

## Question
Can a branch/PR name reaching `ParseRemoteTrackingRef` in [git/client.go](git/client.go#L604) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [git/client.go:604](git/client.go#L604) - `ParseRemoteTrackingRef`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
