# Q2383: binary extension asset path/name unvalidated - NewCmdExtension in command.go

## Question
Does `NewCmdExtension` in [pkg/cmd/extension/command.go](pkg/cmd/extension/command.go#L28) use the release asset name or manifest field from the extension repository as the local filename or executable path?

## Target
- File/function: [pkg/cmd/extension/command.go:28](pkg/cmd/extension/command.go#L28) - `NewCmdExtension`
- Entrypoint: gh extension command
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a release whose asset name contains traversal or targets an existing binary.
- Invariant to test: Local names are derived from the extension name gh computed, not from remote fields.
- Expected Immunefi impact: Critical - Arbitrary file write or overwrite outside the intended directory, escalating to code execution via startup files, git hooks, or gh's own config
- Fast validation: Table test with hostile asset names asserting the written path.
