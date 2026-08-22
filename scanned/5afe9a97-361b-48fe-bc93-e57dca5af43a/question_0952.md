# Q0952: symlink/dev install escape - possibleDists in manager.go

## Question
Can the symlink or local-install handling in `possibleDists` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L799) be driven by remote metadata to link a path outside the extensions directory?

## Target
- File/function: [pkg/cmd/extension/manager.go:799](pkg/cmd/extension/manager.go#L799) - `possibleDists`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish content whose name resolves outside the extension root.
- Invariant to test: Link creation validates both source and target inside the extension root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting rejection of out-of-root link targets.
