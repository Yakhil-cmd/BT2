# Q2204: timeout/EOF treated as approval - Login in login_flow.go

## Question
Does an EOF or closed stdin in `Login` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L50) resolve to the affirmative branch?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:50](pkg/cmd/auth/shared/login_flow.go#L50) - `Login`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Run the flow with stdin closed, as in a CI pipeline processing attacker content.
- Invariant to test: EOF is an error, never a yes.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a closed stdin asserting an error.
