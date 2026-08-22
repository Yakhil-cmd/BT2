# Q3047: timeout/EOF treated as approval - (promptingPRResolver).Resolve in checkout.go

## Question
Does an EOF or closed stdin in `Resolve` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L436) resolve to the affirmative branch?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:436](pkg/cmd/pr/checkout/checkout.go#L436) - `(promptingPRResolver).Resolve`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Run the flow with stdin closed, as in a CI pipeline processing attacker content.
- Invariant to test: EOF is an error, never a yes.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a closed stdin asserting an error.
