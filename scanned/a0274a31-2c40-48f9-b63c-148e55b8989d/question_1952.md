# Q1952: prompt/output spoofing with CR and newline - NewUntrustedBytes in untrusted.go

## Question
Can carriage returns or newlines in an issue/PR title, body, comment, check output, or release note the attacker authored rendered by `NewUntrustedBytes` in [pkg/iostreams/untrusted.go](pkg/iostreams/untrusted.go#L31) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/iostreams/untrusted.go:31](pkg/iostreams/untrusted.go#L31) - `NewUntrustedBytes`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
