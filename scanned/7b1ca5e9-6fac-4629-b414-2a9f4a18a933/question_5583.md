# Q5583: unauthenticated fallback on error - (remoteGitClient).LastCommit in browse.go

## Question
When authentication fails inside `LastCommit` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L375), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/browse/browse.go:375](pkg/cmd/browse/browse.go#L375) - `(remoteGitClient).LastCommit`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
