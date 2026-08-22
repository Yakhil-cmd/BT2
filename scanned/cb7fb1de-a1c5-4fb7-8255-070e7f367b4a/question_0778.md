# Q0778: security decision from response field - GetCurrentLogin in login_flow.go

## Question
Does `GetCurrentLogin` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L253) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:253](pkg/cmd/auth/shared/login_flow.go#L253) - `GetCurrentLogin`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
