# Q1015: ext::/protocol handler in remote URL - IsFullyQualifiedRef in discovery.go

## Question
Can a remote or submodule URL reaching `IsFullyQualifiedRef` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L132) use `ext::`, `file://`, or another protocol whose handler executes a command during fetch/clone?

## Target
- File/function: [internal/skills/discovery/discovery.go:132](internal/skills/discovery/discovery.go#L132) - `IsFullyQualifiedRef`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repository whose `.gitmodules` or remote uses `ext::sh -c ...` and let the victim run gh skills install.
- Invariant to test: Only https/ssh URLs on validated hosts are handed to git; `protocol.*.allow` is not widened.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting non-allowlisted schemes are rejected before invoking git.
