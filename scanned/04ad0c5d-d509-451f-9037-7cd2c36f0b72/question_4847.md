# Q4847: unauthenticated fallback on error - NewCmdView in view.go

## Question
When authentication fails inside `NewCmdView` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L42), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/issue/view/view.go:42](pkg/cmd/issue/view/view.go#L42) - `NewCmdView`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
