# Q2721: prompt/output spoofing with CR and newline - formatHiddenComment in comments.go

## Question
Can carriage returns or newlines in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `formatHiddenComment` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L197) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:197](pkg/cmd/pr/shared/comments.go#L197) - `formatHiddenComment`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
