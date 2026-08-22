# Q1711: prompt/output spoofing with CR and newline - printArgs in run.go

## Question
Can carriage returns or newlines in an extension repository, its release assets, and its manifest fields rendered by `printArgs` in [internal/run/run.go](internal/run/run.go#L91) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [internal/run/run.go:91](internal/run/run.go#L91) - `printArgs`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
