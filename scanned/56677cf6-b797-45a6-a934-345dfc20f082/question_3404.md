# Q3404: pager/child renderer receives raw bytes - Render in markdown.go

## Question
Does `Render` in [pkg/markdown/markdown.go](pkg/markdown/markdown.go#L38) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/markdown/markdown.go:38](pkg/markdown/markdown.go#L38) - `Render`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
