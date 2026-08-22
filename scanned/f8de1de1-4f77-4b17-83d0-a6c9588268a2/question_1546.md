# Q1546: prompt bypassed by config/flag from remote content - newPrompter in default.go

## Question
Can a value originating in remote content (skill/extension/codespace metadata) reaching `newPrompter` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L256) disable the confirmation entirely?

## Target
- File/function: [pkg/cmd/factory/default.go:256](pkg/cmd/factory/default.go#L256) - `newPrompter`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish content that sets the field gh consults for auto-confirm.
- Invariant to test: Confirmation suppression may only come from local flags/config.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting remote fields cannot suppress the prompt.
