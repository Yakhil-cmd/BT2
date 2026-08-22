# Q1514: pager/child renderer receives raw bytes - ExtractHeader in http_client.go

## Question
Does `ExtractHeader` in [api/http_client.go](api/http_client.go#L175) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [api/http_client.go:175](api/http_client.go#L175) - `ExtractHeader`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
