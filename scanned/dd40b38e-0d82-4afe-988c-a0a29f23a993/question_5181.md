# Q5181: GraphQL query assembled from remote strings - checkoutRun in checkout.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes reach the query/variable construction in `checkoutRun` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L112) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:112](pkg/cmd/pr/checkout/checkout.go#L112) - `checkoutRun`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
