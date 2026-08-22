# Q5857: submodule/recursive flag propagation - checkoutBranch in develop.go

## Question
Does `checkoutBranch` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L353) add recursive submodule handling to a git invocation on attacker-published repositories, expanding the attack surface to arbitrary URLs in `.gitmodules`?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:353](pkg/cmd/issue/develop/develop.go#L353) - `checkoutBranch`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish a repo with hostile submodule URLs.
- Invariant to test: Recursive operations are opt-in and host-validated.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the argv does not enable recursion by default.
