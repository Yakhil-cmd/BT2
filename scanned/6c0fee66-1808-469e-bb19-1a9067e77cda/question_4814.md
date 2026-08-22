# Q4814: pager/child renderer receives raw bytes - (IOStreams).StartProgressIndicatorWithLabel in iostreams.go

## Question
Does `StartProgressIndicatorWithLabel` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L303) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/iostreams/iostreams.go:303](pkg/iostreams/iostreams.go#L303) - `(IOStreams).StartProgressIndicatorWithLabel`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
