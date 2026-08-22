# Q4671: checkout of attacker-controlled path or worktree - detectGitHubRemote in publish.go

## Question
Can a branch/PR name reaching `detectGitHubRemote` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L978) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:978](pkg/cmd/skills/publish/publish.go#L978) - `detectGitHubRemote`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
