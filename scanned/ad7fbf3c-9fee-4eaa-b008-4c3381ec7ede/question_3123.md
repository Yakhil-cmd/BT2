# Q3123: prompt/output spoofing with CR and newline - NewCmdExtension in extension.go

## Question
Can carriage returns or newlines in an extension repository, its release assets, and its manifest fields rendered by `NewCmdExtension` in [pkg/cmd/root/extension.go](pkg/cmd/root/extension.go#L22) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/root/extension.go:22](pkg/cmd/root/extension.go#L22) - `NewCmdExtension`
- Entrypoint: gh root extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
