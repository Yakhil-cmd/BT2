# Q1790: pager/child renderer receives raw bytes - NewCmdPreview in preview.go

## Question
Does `NewCmdPreview` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L44) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:44](pkg/cmd/skills/preview/preview.go#L44) - `NewCmdPreview`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
