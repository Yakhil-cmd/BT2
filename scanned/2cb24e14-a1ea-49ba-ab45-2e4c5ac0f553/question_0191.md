# Q0191: index/label mismatch after filtering - (promptingPRResolver).Resolve in checkout.go

## Question
Can the option list built in `Resolve` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L436) be filtered or deduplicated so the chosen index maps to a different underlying object than the label shown?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:436](pkg/cmd/pr/checkout/checkout.go#L436) - `(promptingPRResolver).Resolve`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish entries whose labels collide after truncation/dedup.
- Invariant to test: Selection returns the object identity, not a recomputed index.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with colliding labels asserting the selected object matches the label.
