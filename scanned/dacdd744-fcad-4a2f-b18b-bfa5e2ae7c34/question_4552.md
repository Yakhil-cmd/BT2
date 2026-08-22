# Q4552: symlink/dev install escape - NewCmdShellAlias in alias.go

## Question
Can the symlink or local-install handling in `NewCmdShellAlias` in [pkg/cmd/root/alias.go](pkg/cmd/root/alias.go#L20) be driven by remote metadata to link a path outside the extensions directory?

## Target
- File/function: [pkg/cmd/root/alias.go:20](pkg/cmd/root/alias.go#L20) - `NewCmdShellAlias`
- Entrypoint: gh root alias
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish content whose name resolves outside the extension root.
- Invariant to test: Link creation validates both source and target inside the extension root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting rejection of out-of-root link targets.
