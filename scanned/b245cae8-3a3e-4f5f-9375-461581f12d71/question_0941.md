# Q0941: checkout of attacker-controlled path or worktree - (Manager).upgradeExtension in manager.go

## Question
Can a branch/PR name reaching `upgradeExtension` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L520) determine a worktree or directory path, letting the checkout land outside the repository?

## Target
- File/function: [pkg/cmd/extension/manager.go:520](pkg/cmd/extension/manager.go#L520) - `(Manager).upgradeExtension`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a PR whose head ref contains traversal segments.
- Invariant to test: Derived paths are sanitized and confined to the repo/worktree root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test over hostile ref names asserting the resolved path stays inside the root.
