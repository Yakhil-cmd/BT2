# Q4564: symlink/dev install escape - (cmdWithStderr).Output in run.go

## Question
Can the symlink or local-install handling in `Output` in [internal/run/run.go](internal/run/run.go#L33) be driven by remote metadata to link a path outside the extensions directory?

## Target
- File/function: [internal/run/run.go:33](internal/run/run.go#L33) - `(cmdWithStderr).Output`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish content whose name resolves outside the extension root.
- Invariant to test: Link creation validates both source and target inside the extension root.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Test asserting rejection of out-of-root link targets.
