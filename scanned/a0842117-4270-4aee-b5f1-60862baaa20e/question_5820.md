# Q5820: clone of an attacker repo executes code - simplifyURL in clone.go

## Question
Does the flow through `simplifyURL` in [pkg/cmd/repo/clone/clone.go](pkg/cmd/repo/clone/clone.go#L249) run git in a way that lets a hostile repository's own contents (hooks, .gitmodules, .gitattributes filters, symlinked .git) execute during or right after gh repo clone?

## Target
- File/function: [pkg/cmd/repo/clone/clone.go:249](pkg/cmd/repo/clone/clone.go#L249) - `simplifyURL`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo carrying the payload and let the victim clone it with gh.
- Invariant to test: gh disables hook/filter execution paths it does not need and never runs post-clone logic from repo content.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Integration test cloning a fixture repo with hooks/filters asserting nothing executes.
