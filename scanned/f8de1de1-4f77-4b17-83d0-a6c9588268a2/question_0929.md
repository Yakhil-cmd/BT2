# Q0929: ext::/protocol handler in remote URL - cloneRun in clone.go

## Question
Can a remote or submodule URL reaching `cloneRun` in [pkg/cmd/gist/clone/clone.go](pkg/cmd/gist/clone/clone.go#L75) use `ext::`, `file://`, or another protocol whose handler executes a command during fetch/clone?

## Target
- File/function: [pkg/cmd/gist/clone/clone.go:75](pkg/cmd/gist/clone/clone.go#L75) - `cloneRun`
- Entrypoint: gh gist clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repository whose `.gitmodules` or remote uses `ext::sh -c ...` and let the victim run gh gist clone.
- Invariant to test: Only https/ssh URLs on validated hosts are handed to git; `protocol.*.allow` is not widened.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting non-allowlisted schemes are rejected before invoking git.
