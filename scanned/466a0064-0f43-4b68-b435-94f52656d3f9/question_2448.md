# Q2448: ext::/protocol handler in remote URL - resolveTagRef in discovery.go

## Question
Can a remote or submodule URL reaching `resolveTagRef` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L276) use `ext::`, `file://`, or another protocol whose handler executes a command during fetch/clone?

## Target
- File/function: [internal/skills/discovery/discovery.go:276](internal/skills/discovery/discovery.go#L276) - `resolveTagRef`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repository whose `.gitmodules` or remote uses `ext::sh -c ...` and let the victim run gh skills install.
- Invariant to test: Only https/ssh URLs on validated hosts are handed to git; `protocol.*.allow` is not widened.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting non-allowlisted schemes are rejected before invoking git.
