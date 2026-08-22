# Q5825: submodule/recursive flag propagation - NewCmdSync in sync.go

## Question
Does `NewCmdSync` in [pkg/cmd/repo/sync/sync.go](pkg/cmd/repo/sync/sync.go#L36) add recursive submodule handling to a git invocation on attacker-published repositories, expanding the attack surface to arbitrary URLs in `.gitmodules`?

## Target
- File/function: [pkg/cmd/repo/sync/sync.go:36](pkg/cmd/repo/sync/sync.go#L36) - `NewCmdSync`
- Entrypoint: gh repo sync
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo with hostile submodule URLs.
- Invariant to test: Recursive operations are opt-in and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the argv does not enable recursion by default.
