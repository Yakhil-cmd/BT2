# Q0838: pager/child renderer receives raw bytes - apiRun in api.go

## Question
Does `apiRun` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L307) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/api/api.go:307](pkg/cmd/api/api.go#L307) - `apiRun`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
