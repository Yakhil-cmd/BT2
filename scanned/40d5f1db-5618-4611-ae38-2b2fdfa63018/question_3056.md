# Q3056: unauthenticated fallback on error - preloadPrReviews in finder.go

## Question
When authentication fails inside `preloadPrReviews` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L444), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:444](pkg/cmd/pr/shared/finder.go#L444) - `preloadPrReviews`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
