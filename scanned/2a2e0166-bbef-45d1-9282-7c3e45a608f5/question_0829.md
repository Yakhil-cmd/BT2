# Q0829: prompt/output spoofing with CR and newline - externalHttpClientFunc in default.go

## Question
Can carriage returns or newlines in a repo/remote/host string or API response field the attacker publishes rendered by `externalHttpClientFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L230) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/factory/default.go:230](pkg/cmd/factory/default.go#L230) - `externalHttpClientFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
