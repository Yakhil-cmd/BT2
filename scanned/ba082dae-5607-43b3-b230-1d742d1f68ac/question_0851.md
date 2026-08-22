# Q0851: scope/permission check bypass - CredentialPatternFromHost in client.go

## Question
Does `CredentialPatternFromHost` in [git/client.go](git/client.go#L134) make a security decision from a scope/permission value returned by the server (or absent header) that a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes can influence?

## Target
- File/function: [git/client.go:134](git/client.go#L134) - `CredentialPatternFromHost`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Return an inflated or empty `X-OAuth-Scopes` from an attacker-controlled host so gh skips a confirmation.
- Invariant to test: Local privilege decisions never depend on unauthenticated, attacker-supplied response data.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: httpmock test with forged scope headers asserting gh still enforces the check.
