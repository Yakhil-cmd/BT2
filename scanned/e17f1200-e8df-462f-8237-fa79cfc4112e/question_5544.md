# Q5544: prompt/output spoofing with CR and newline - Render in markdown.go

## Question
Can carriage returns or newlines in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `Render` in [pkg/markdown/markdown.go](pkg/markdown/markdown.go#L38) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/markdown/markdown.go:38](pkg/markdown/markdown.go#L38) - `Render`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
