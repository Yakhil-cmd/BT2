# Q3495: prompt/output spoofing with CR and newline - newSSHCmd in ssh.go

## Question
Can carriage returns or newlines in codespace/API response fields and everything the codespace-side process sends back rendered by `newSSHCmd` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L49) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:49](pkg/cmd/codespace/ssh.go#L49) - `newSSHCmd`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
