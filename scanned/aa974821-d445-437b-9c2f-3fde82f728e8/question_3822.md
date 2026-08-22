# Q3822: ext::/protocol handler in remote URL - (gitExecuter).Remotes in git.go

## Question
Can a remote or submodule URL reaching `Remotes` in [pkg/cmd/extension/git.go](pkg/cmd/extension/git.go#L58) use `ext::`, `file://`, or another protocol whose handler executes a command during fetch/clone?

## Target
- File/function: [pkg/cmd/extension/git.go:58](pkg/cmd/extension/git.go#L58) - `(gitExecuter).Remotes`
- Entrypoint: gh extension git
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a repository whose `.gitmodules` or remote uses `ext::sh -c ...` and let the victim run gh extension git.
- Invariant to test: Only https/ssh URLs on validated hosts are handed to git; `protocol.*.allow` is not widened.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting non-allowlisted schemes are rejected before invoking git.
