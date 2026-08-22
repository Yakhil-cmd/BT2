# Q5457: prompt/output spoofing with CR and newline - verifyRun in verify.go

## Question
Can carriage returns or newlines in an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims rendered by `verifyRun` in [pkg/cmd/release/verify/verify.go](pkg/cmd/release/verify/verify.go#L118) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/release/verify/verify.go:118](pkg/cmd/release/verify/verify.go#L118) - `verifyRun`
- Entrypoint: gh release verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
