# Q2920: unbounded response body - GetCurrentLogin in login_flow.go

## Question
Does `GetCurrentLogin` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L253) read the whole response body into memory without a limit, so an attacker-controlled endpoint can exhaust the victim's RAM?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:253](pkg/cmd/auth/shared/login_flow.go#L253) - `GetCurrentLogin`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Serve a multi-gigabyte body from an attacker-controlled host or asset URL.
- Invariant to test: Response reads are wrapped in a limit reader with an explicit cap.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a huge/endless body asserting a bounded error.
