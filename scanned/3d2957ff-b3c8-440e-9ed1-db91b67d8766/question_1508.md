# Q1508: scope/permission check bypass - clientOptions in client.go

## Question
Does `clientOptions` in [api/client.go](api/client.go#L256) make a security decision from a scope/permission value returned by the server (or absent header) that a repo/remote/host string or API response field the attacker publishes can influence?

## Target
- File/function: [api/client.go:256](api/client.go#L256) - `clientOptions`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Return an inflated or empty `X-OAuth-Scopes` from an attacker-controlled host so gh skips a confirmation.
- Invariant to test: Local privilege decisions never depend on unauthenticated, attacker-supplied response data.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: httpmock test with forged scope headers asserting gh still enforces the check.
