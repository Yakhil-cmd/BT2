# Q0489: checkout of attacker-controlled path or worktree - populateLogSegments in logs.go

## Question
Can a branch/PR name reaching `populateLogSegments` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L95) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [pkg/cmd/run/view/logs.go:95](pkg/cmd/run/view/logs.go#L95) - `populateLogSegments`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
