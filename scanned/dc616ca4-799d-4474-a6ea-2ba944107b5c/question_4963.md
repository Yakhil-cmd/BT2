# Q4963: pager/child renderer receives raw bytes - runCopilot in copilot.go

## Question
Does `runCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L134) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:134](pkg/cmd/copilot/copilot.go#L134) - `runCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
