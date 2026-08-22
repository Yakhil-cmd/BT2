# Q5831: prompt bypassed by config/flag from remote content - setDefaultRun in setdefault.go

## Question
Can a value originating in remote content (skill/extension/codespace metadata) reaching `setDefaultRun` in [pkg/cmd/repo/setdefault/setdefault.go](pkg/cmd/repo/setdefault/setdefault.go#L126) disable the confirmation entirely?

## Target
- File/function: [pkg/cmd/repo/setdefault/setdefault.go:126](pkg/cmd/repo/setdefault/setdefault.go#L126) - `setDefaultRun`
- Entrypoint: gh repo setdefault
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish content that sets the field gh consults for auto-confirm.
- Invariant to test: Confirmation suppression may only come from local flags/config.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting remote fields cannot suppress the prompt.
