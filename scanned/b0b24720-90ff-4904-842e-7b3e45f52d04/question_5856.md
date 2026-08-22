# Q5856: unauthenticated fallback on error - developRunList in develop.go

## Question
When authentication fails inside `developRunList` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L319), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:319](pkg/cmd/issue/develop/develop.go#L319) - `developRunList`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
