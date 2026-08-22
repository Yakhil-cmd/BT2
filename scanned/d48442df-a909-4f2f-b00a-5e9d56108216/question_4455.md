# Q4455: ext::/protocol handler in remote URL - forkRun in fork.go

## Question
Can a remote or submodule URL reaching `forkRun` in [pkg/cmd/repo/fork/fork.go](pkg/cmd/repo/fork/fork.go#L159) use `ext::`, `file://`, or another protocol whose handler executes a command during fetch/clone?

## Target
- File/function: [pkg/cmd/repo/fork/fork.go:159](pkg/cmd/repo/fork/fork.go#L159) - `forkRun`
- Entrypoint: gh repo fork
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repository whose `.gitmodules` or remote uses `ext::sh -c ...` and let the victim run gh repo fork.
- Invariant to test: Only https/ssh URLs on validated hosts are handed to git; `protocol.*.allow` is not widened.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting non-allowlisted schemes are rejected before invoking git.
