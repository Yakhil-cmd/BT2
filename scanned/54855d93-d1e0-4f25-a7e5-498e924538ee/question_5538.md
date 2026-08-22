# Q5538: prompt/output spoofing with CR and newline - BinaryContentType in content.go

## Question
Can carriage returns or newlines in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `BinaryContentType` in [pkg/iostreams/content.go](pkg/iostreams/content.go#L24) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/iostreams/content.go:24](pkg/iostreams/content.go#L24) - `BinaryContentType`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
