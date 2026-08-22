# Q4944: prompt/output spoofing with CR and newline - NewApp in common.go

## Question
Can carriage returns or newlines in codespace/API response fields and everything the codespace-side process sends back rendered by `NewApp` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L40) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/codespace/common.go:40](pkg/cmd/codespace/common.go#L40) - `NewApp`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
