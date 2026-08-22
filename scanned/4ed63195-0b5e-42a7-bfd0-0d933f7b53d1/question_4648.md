# Q4648: prompt/output spoofing with CR and newline - renderInteractive in preview.go

## Question
Can carriage returns or newlines in a published skill's archive entries, frontmatter, and registry metadata rendered by `renderInteractive` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L318) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:318](pkg/cmd/skills/preview/preview.go#L318) - `renderInteractive`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
