# Q1352: prompt/output spoofing with CR and newline - (API).withRetry in api.go

## Question
Can carriage returns or newlines in codespace/API response fields and everything the codespace-side process sends back rendered by `withRetry` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1299) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [internal/codespaces/api/api.go:1299](internal/codespaces/api/api.go#L1299) - `(API).withRetry`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
