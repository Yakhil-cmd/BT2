# Q1394: prompt bypassed by config/flag from remote content - runCopilot in copilot.go

## Question
Can a value originating in remote content (skill/extension/codespace metadata) reaching `runCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L134) disable the confirmation entirely?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:134](pkg/cmd/copilot/copilot.go#L134) - `runCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish content that sets the field gh consults for auto-confirm.
- Invariant to test: Confirmation suppression may only come from local flags/config.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting remote fields cannot suppress the prompt.
