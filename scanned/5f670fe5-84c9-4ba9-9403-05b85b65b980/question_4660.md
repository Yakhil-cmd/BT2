# Q4660: ext::/protocol handler in remote URL - runPublishRelease in publish.go

## Question
Can a remote or submodule URL reaching `runPublishRelease` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L481) use `ext::`, `file://`, or another protocol whose handler executes a command during fetch/clone?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:481](pkg/cmd/skills/publish/publish.go#L481) - `runPublishRelease`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a repository whose `.gitmodules` or remote uses `ext::sh -c ...` and let the victim run gh skills publish.
- Invariant to test: Only https/ssh URLs on validated hosts are handed to git; `protocol.*.allow` is not widened.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting non-allowlisted schemes are rejected before invoking git.
