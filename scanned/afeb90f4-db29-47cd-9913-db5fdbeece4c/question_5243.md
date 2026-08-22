# Q5243: ext::/protocol handler in remote URL - (Extension).Owner in extension.go

## Question
Can a remote or submodule URL reaching `Owner` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L182) use `ext::`, `file://`, or another protocol whose handler executes a command during fetch/clone?

## Target
- File/function: [pkg/cmd/extension/extension.go:182](pkg/cmd/extension/extension.go#L182) - `(Extension).Owner`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a repository whose `.gitmodules` or remote uses `ext::sh -c ...` and let the victim run gh extension extension.
- Invariant to test: Only https/ssh URLs on validated hosts are handed to git; `protocol.*.allow` is not widened.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting non-allowlisted schemes are rejected before invoking git.
