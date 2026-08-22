# Q4527: extension dispatch resolves an attacker binary - (Extension).CurrentVersion in extension.go

## Question
Can `CurrentVersion` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L88) dispatch `gh <name>` to an executable whose path or name was influenced by extension metadata rather than by the validated install directory?

## Target
- File/function: [pkg/cmd/extension/extension.go:88](pkg/cmd/extension/extension.go#L88) - `(Extension).CurrentVersion`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension whose metadata makes gh resolve a different file.
- Invariant to test: Dispatch resolves strictly to `<extdir>/gh-<name>/gh-<name>`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the executed path for hostile metadata.
