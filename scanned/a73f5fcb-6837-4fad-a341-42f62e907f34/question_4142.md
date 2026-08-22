# Q4142: prompt/output spoofing with CR and newline - PrintMessage in display.go

## Question
Can carriage returns or newlines in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `PrintMessage` in [pkg/cmd/pr/shared/display.go](pkg/cmd/pr/shared/display.go#L62) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/pr/shared/display.go:62](pkg/cmd/pr/shared/display.go#L62) - `PrintMessage`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
