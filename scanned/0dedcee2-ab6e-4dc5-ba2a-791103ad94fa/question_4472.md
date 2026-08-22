# Q4472: OAuth callback/state validation - executeCmds in checkout.go

## Question
Does the browser/device flow driven by `executeCmds` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L356) accept a callback or device response without binding state, PKCE, or the originating host?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:356](pkg/cmd/pr/checkout/checkout.go#L356) - `executeCmds`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Feed the local callback listener a forged request so gh stores an attacker-issued token for the victim's host.
- Invariant to test: Callbacks are accepted only with a matching state and from the flow gh initiated.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test posting a forged callback with a wrong state and asserting rejection.
