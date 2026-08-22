# Q3064: clone of an attacker repo executes code - developRunCreate in develop.go

## Question
Does the flow through `developRunCreate` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L201) run git in a way that lets a hostile repository's own contents (hooks, .gitmodules, .gitattributes filters, symlinked .git) execute during or right after gh issue develop?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:201](pkg/cmd/issue/develop/develop.go#L201) - `developRunCreate`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo carrying the payload and let the victim clone it with gh.
- Invariant to test: gh disables hook/filter execution paths it does not need and never runs post-clone logic from repo content.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Integration test cloning a fixture repo with hooks/filters asserting nothing executes.
