# Q1354: prompt bypassed by config/flag from remote content - (App).SSH in ssh.go

## Question
Can a value originating in remote content (skill/extension/codespace metadata) reaching `SSH` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L165) disable the confirmation entirely?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:165](pkg/cmd/codespace/ssh.go#L165) - `(App).SSH`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish content that sets the field gh consults for auto-confirm.
- Invariant to test: Confirmation suppression may only come from local flags/config.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting remote fields cannot suppress the prompt.
