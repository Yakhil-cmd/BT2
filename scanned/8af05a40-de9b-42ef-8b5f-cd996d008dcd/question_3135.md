# Q3135: symlink/dev install escape - executable in cmd.go

## Question
Can the symlink or local-install handling in `executable` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L444) be driven by remote metadata to link a path outside the extensions directory?

## Target
- File/function: [internal/ghcmd/cmd.go:444](internal/ghcmd/cmd.go#L444) - `executable`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish content whose name resolves outside the extension root.
- Invariant to test: Link creation validates both source and target inside the extension root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting rejection of out-of-root link targets.
