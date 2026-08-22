# Q4584: checkout of attacker-controlled path or worktree - IsFullyQualifiedRef in discovery.go

## Question
Can a branch/PR name reaching `IsFullyQualifiedRef` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L132) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [internal/skills/discovery/discovery.go:132](internal/skills/discovery/discovery.go#L132) - `IsFullyQualifiedRef`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
