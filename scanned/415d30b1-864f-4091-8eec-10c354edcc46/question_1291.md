# Q1291: pager/child renderer receives raw bytes - formatComment in comments.go

## Question
Does `formatComment` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L89) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:89](pkg/cmd/pr/shared/comments.go#L89) - `formatComment`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
