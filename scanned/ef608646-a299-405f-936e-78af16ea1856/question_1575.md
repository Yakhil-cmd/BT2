# Q1575: ext::/protocol handler in remote URL - parseBranchConfig in client.go

## Question
Can a remote or submodule URL reaching `parseBranchConfig` in [git/client.go](git/client.go#L453) use `ext::`, `file://`, or another protocol whose handler executes a command during fetch/clone?

## Target
- File/function: [git/client.go:453](git/client.go#L453) - `parseBranchConfig`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repository whose `.gitmodules` or remote uses `ext::sh -c ...` and let the victim run gh repo clone.
- Invariant to test: Only https/ssh URLs on validated hosts are handed to git; `protocol.*.allow` is not widened.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting non-allowlisted schemes are rejected before invoking git.
