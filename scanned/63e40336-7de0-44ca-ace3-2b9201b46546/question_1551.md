# Q1551: scope/permission check bypass - NewCmdApi in api.go

## Question
Does `NewCmdApi` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L66) make a security decision from a scope/permission value returned by the server (or absent header) that a repo/remote/host string or API response field the attacker publishes can influence?

## Target
- File/function: [pkg/cmd/api/api.go:66](pkg/cmd/api/api.go#L66) - `NewCmdApi`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return an inflated or empty `X-OAuth-Scopes` from an attacker-controlled host so gh skips a confirmation.
- Invariant to test: Local privilege decisions never depend on unauthenticated, attacker-supplied response data.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: httpmock test with forged scope headers asserting gh still enforces the check.
