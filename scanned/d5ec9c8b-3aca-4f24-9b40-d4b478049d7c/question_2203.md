# Q2203: prompt bypassed by config/flag from remote content - helperRun in helper.go

## Question
Can a value originating in remote content (skill/extension/codespace metadata) reaching `helperRun` in [pkg/cmd/auth/gitcredential/helper.go](pkg/cmd/auth/gitcredential/helper.go#L58) disable the confirmation entirely?

## Target
- File/function: [pkg/cmd/auth/gitcredential/helper.go:58](pkg/cmd/auth/gitcredential/helper.go#L58) - `helperRun`
- Entrypoint: gh auth gitcredential
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish content that sets the field gh consults for auto-confirm.
- Invariant to test: Confirmation suppression may only come from local flags/config.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting remote fields cannot suppress the prompt.
