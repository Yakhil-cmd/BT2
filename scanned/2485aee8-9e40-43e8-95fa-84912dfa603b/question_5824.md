# Q5824: ext::/protocol handler in remote URL - (gitExecuter).Fetch in git.go

## Question
Can a remote or submodule URL reaching `Fetch` in [pkg/cmd/repo/sync/git.go](pkg/cmd/repo/sync/git.go#L56) use `ext::`, `file://`, or another protocol whose handler executes a command during fetch/clone?

## Target
- File/function: [pkg/cmd/repo/sync/git.go:56](pkg/cmd/repo/sync/git.go#L56) - `(gitExecuter).Fetch`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repository whose `.gitmodules` or remote uses `ext::sh -c ...` and let the victim run gh repo sync.
- Invariant to test: Only https/ssh URLs on validated hosts are handed to git; `protocol.*.allow` is not widened.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting non-allowlisted schemes are rejected before invoking git.
