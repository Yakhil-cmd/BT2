# Q3619: prompt bypassed by config/flag from remote content - promptForHostname in login.go

## Question
Can a value originating in remote content (skill/extension/codespace metadata) reaching `promptForHostname` in [pkg/cmd/auth/login/login.go](pkg/cmd/auth/login/login.go#L247) disable the confirmation entirely?

## Target
- File/function: [pkg/cmd/auth/login/login.go:247](pkg/cmd/auth/login/login.go#L247) - `promptForHostname`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish content that sets the field gh consults for auto-confirm.
- Invariant to test: Confirmation suppression may only come from local flags/config.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting remote fields cannot suppress the prompt.
