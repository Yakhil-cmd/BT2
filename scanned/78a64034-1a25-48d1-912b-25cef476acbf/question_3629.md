# Q3629: prompt/output spoofing with CR and newline - setupGitRun in setupgit.go

## Question
Can carriage returns or newlines in a hostname, OAuth/device response, or git credential-protocol input the attacker supplies rendered by `setupGitRun` in [pkg/cmd/auth/setupgit/setupgit.go](pkg/cmd/auth/setupgit/setupgit.go#L75) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/auth/setupgit/setupgit.go:75](pkg/cmd/auth/setupgit/setupgit.go#L75) - `setupGitRun`
- Entrypoint: gh auth setupgit
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
