# Q2918: pager/child renderer receives raw bytes - Login in login_flow.go

## Question
Does `Login` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L50) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:50](pkg/cmd/auth/shared/login_flow.go#L50) - `Login`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
