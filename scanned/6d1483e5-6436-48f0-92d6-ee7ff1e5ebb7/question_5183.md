# Q5183: branch config write from PR data - cmdsForMissingRemote in checkout.go

## Question
Can `cmdsForMissingRemote` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L244) write PR-derived values into `.git/config` (branch.*.remote/merge/pushRemote) without excluding newlines or section-breaking characters?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:244](pkg/cmd/pr/checkout/checkout.go#L244) - `cmdsForMissingRemote`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Open a PR with a head ref containing a newline and a forged config line.
- Invariant to test: Config values are validated and written via git config, not by string assembly.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting rejection of newline-bearing ref names.
