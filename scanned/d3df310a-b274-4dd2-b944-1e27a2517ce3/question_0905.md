# Q0905: host shown differs from host used - (promptingPRResolver).Resolve in checkout.go

## Question
Does the confirmation in `Resolve` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L436) display a host/repo string that is derived differently from the value actually used afterwards?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:436](pkg/cmd/pr/checkout/checkout.go#L436) - `(promptingPRResolver).Resolve`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish coordinates where display and action diverge (lookalike host, renamed repo).
- Invariant to test: Displayed and acted-on identifiers come from the same variable.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the prompt string and the executed target are the same value.
