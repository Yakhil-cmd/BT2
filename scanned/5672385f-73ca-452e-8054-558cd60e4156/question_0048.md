# Q0048: pager/child renderer receives raw bytes - loginRun in login.go

## Question
Does `loginRun` in [pkg/cmd/auth/login/login.go](pkg/cmd/auth/login/login.go#L168) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/auth/login/login.go:168](pkg/cmd/auth/login/login.go#L168) - `loginRun`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
