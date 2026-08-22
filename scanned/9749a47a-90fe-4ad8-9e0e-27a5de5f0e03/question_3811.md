# Q3811: extension dispatch resolves an attacker binary - NewCmdExtension in command.go

## Question
Can `NewCmdExtension` in [pkg/cmd/extension/command.go](pkg/cmd/extension/command.go#L28) dispatch `gh <name>` to an executable whose path or name was influenced by extension metadata rather than by the validated install directory?

## Target
- File/function: [pkg/cmd/extension/command.go:28](pkg/cmd/extension/command.go#L28) - `NewCmdExtension`
- Entrypoint: gh extension command
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension whose metadata makes gh resolve a different file.
- Invariant to test: Dispatch resolves strictly to `<extdir>/gh-<name>/gh-<name>`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the executed path for hostile metadata.
