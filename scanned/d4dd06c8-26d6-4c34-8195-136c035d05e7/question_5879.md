# Q5879: symlink/dev install escape - NewCmdExtension in command.go

## Question
Can the symlink or local-install handling in `NewCmdExtension` in [pkg/cmd/extension/command.go](pkg/cmd/extension/command.go#L28) be driven by remote metadata to link a path outside the extensions directory?

## Target
- File/function: [pkg/cmd/extension/command.go:28](pkg/cmd/extension/command.go#L28) - `NewCmdExtension`
- Entrypoint: gh extension command
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish content whose name resolves outside the extension root.
- Invariant to test: Link creation validates both source and target inside the extension root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting rejection of out-of-root link targets.
