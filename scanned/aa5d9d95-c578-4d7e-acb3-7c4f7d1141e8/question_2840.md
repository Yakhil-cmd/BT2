# Q2840: prompt/output spoofing with CR and newline - setRun in set.go

## Question
Can carriage returns or newlines in an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes rendered by `setRun` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L203) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/secret/set/set.go:203](pkg/cmd/secret/set/set.go#L203) - `setRun`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
