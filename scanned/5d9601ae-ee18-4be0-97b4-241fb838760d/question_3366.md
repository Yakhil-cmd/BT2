# Q3366: prompt bypassed by config/flag from remote content - PromptGists in shared.go

## Question
Can a value originating in remote content (skill/extension/codespace metadata) reaching `PromptGists` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L228) disable the confirmation entirely?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:228](pkg/cmd/gist/shared/shared.go#L228) - `PromptGists`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content that sets the field gh consults for auto-confirm.
- Invariant to test: Confirmation suppression may only come from local flags/config.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting remote fields cannot suppress the prompt.
