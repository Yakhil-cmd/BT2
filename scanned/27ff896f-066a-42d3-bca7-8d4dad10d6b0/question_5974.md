# Q5974: prompt bypassed by config/flag from remote content - updateRun in update.go

## Question
Can a value originating in remote content (skill/extension/codespace metadata) reaching `updateRun` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L143) disable the confirmation entirely?

## Target
- File/function: [pkg/cmd/skills/update/update.go:143](pkg/cmd/skills/update/update.go#L143) - `updateRun`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish content that sets the field gh consults for auto-confirm.
- Invariant to test: Confirmation suppression may only come from local flags/config.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting remote fields cannot suppress the prompt.
