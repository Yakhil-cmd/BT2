# Q4152: prompt/output spoofing with CR and newline - printTable in output.go

## Question
Can carriage returns or newlines in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `printTable` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L94) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:94](pkg/cmd/pr/checks/output.go#L94) - `printTable`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
