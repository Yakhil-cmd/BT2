# Q0827: pager/child renderer receives raw bytes - HttpClientFunc in default.go

## Question
Does `HttpClientFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L188) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/factory/default.go:188](pkg/cmd/factory/default.go#L188) - `HttpClientFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
