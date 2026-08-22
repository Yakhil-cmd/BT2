# Q3756: gh-specific post-clone git commands - cmdsForMissingRemote in checkout.go

## Question
Can attacker-controlled repository metadata (default branch name, remote list, upstream) influence the extra git commands gh runs after gh pr checkout through `cmdsForMissingRemote` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L244)?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:244](pkg/cmd/pr/checkout/checkout.go#L244) - `cmdsForMissingRemote`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Set a default branch named `--exec=...` or containing shell-relevant characters.
- Invariant to test: Names from remote data are validated as refs and passed after `--`.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile default-branch names.
