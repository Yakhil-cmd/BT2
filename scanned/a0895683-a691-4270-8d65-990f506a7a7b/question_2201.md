# Q2201: scope/permission check bypass - setupGitRun in setupgit.go

## Question
Does `setupGitRun` in [pkg/cmd/auth/setupgit/setupgit.go](pkg/cmd/auth/setupgit/setupgit.go#L75) make a security decision from a scope/permission value returned by the server (or absent header) that a hostname, OAuth/device response, or git credential-protocol input the attacker supplies can influence?

## Target
- File/function: [pkg/cmd/auth/setupgit/setupgit.go:75](pkg/cmd/auth/setupgit/setupgit.go#L75) - `setupGitRun`
- Entrypoint: gh auth setupgit
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Return an inflated or empty `X-OAuth-Scopes` from an attacker-controlled host so gh skips a confirmation.
- Invariant to test: Local privilege decisions never depend on unauthenticated, attacker-supplied response data.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: httpmock test with forged scope headers asserting gh still enforces the check.
