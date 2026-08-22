# Q2411: extension dispatch resolves an attacker binary - NewCmdShellAlias in alias.go

## Question
Can `NewCmdShellAlias` in [pkg/cmd/root/alias.go](pkg/cmd/root/alias.go#L20) dispatch `gh <name>` to an executable whose path or name was influenced by extension metadata rather than by the validated install directory?

## Target
- File/function: [pkg/cmd/root/alias.go:20](pkg/cmd/root/alias.go#L20) - `NewCmdShellAlias`
- Entrypoint: gh root alias
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension whose metadata makes gh resolve a different file.
- Invariant to test: Dispatch resolves strictly to `<extdir>/gh-<name>/gh-<name>`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the executed path for hostile metadata.
