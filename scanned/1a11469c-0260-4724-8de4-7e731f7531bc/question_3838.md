# Q3838: pager/child renderer receives raw bytes - NewCmdRoot in root.go

## Question
Does `NewCmdRoot` in [pkg/cmd/root/root.go](pkg/cmd/root/root.go#L64) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/root/root.go:64](pkg/cmd/root/root.go#L64) - `NewCmdRoot`
- Entrypoint: gh root root
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
