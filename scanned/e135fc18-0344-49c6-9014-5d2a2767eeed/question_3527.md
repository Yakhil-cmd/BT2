# Q3527: scope/permission check bypass - CapiClientFunc in capi.go

## Question
Does `CapiClientFunc` in [pkg/cmd/agent-task/shared/capi.go](pkg/cmd/agent-task/shared/capi.go#L21) make a security decision from a scope/permission value returned by the server (or absent header) that an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes can influence?

## Target
- File/function: [pkg/cmd/agent-task/shared/capi.go:21](pkg/cmd/agent-task/shared/capi.go#L21) - `CapiClientFunc`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Return an inflated or empty `X-OAuth-Scopes` from an attacker-controlled host so gh skips a confirmation.
- Invariant to test: Local privilege decisions never depend on unauthenticated, attacker-supplied response data.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: httpmock test with forged scope headers asserting gh still enforces the check.
