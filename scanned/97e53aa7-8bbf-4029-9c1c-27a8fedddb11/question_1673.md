# Q1673: extension dispatch resolves an attacker binary - (Extension).LatestVersion in extension.go

## Question
Can `LatestVersion` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L116) dispatch `gh <name>` to an executable whose path or name was influenced by extension metadata rather than by the validated install directory?

## Target
- File/function: [pkg/cmd/extension/extension.go:116](pkg/cmd/extension/extension.go#L116) - `(Extension).LatestVersion`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an extension whose metadata makes gh resolve a different file.
- Invariant to test: Dispatch resolves strictly to `<extdir>/gh-<name>/gh-<name>`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the executed path for hostile metadata.
