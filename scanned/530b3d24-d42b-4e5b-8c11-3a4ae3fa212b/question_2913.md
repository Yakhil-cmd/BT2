# Q2913: pager/child renderer receives raw bytes - switchRun in switch.go

## Question
Does `switchRun` in [pkg/cmd/auth/switch/switch.go](pkg/cmd/auth/switch/switch.go#L77) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/auth/switch/switch.go:77](pkg/cmd/auth/switch/switch.go#L77) - `switchRun`
- Entrypoint: gh auth switch
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
