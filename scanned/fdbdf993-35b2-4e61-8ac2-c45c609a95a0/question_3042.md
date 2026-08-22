# Q3042: clone of an attacker repo executes code - cmdsForMissingRemote in checkout.go

## Question
Does the flow through `cmdsForMissingRemote` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L244) run git in a way that lets a hostile repository's own contents (hooks, .gitmodules, .gitattributes filters, symlinked .git) execute during or right after gh pr checkout?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:244](pkg/cmd/pr/checkout/checkout.go#L244) - `cmdsForMissingRemote`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo carrying the payload and let the victim clone it with gh.
- Invariant to test: gh disables hook/filter execution paths it does not need and never runs post-clone logic from repo content.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Integration test cloning a fixture repo with hooks/filters asserting nothing executes.
