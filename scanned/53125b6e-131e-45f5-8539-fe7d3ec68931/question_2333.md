# Q2333: prompt bypassed by config/flag from remote content - (promptingPRResolver).Resolve in checkout.go

## Question
Can a value originating in remote content (skill/extension/codespace metadata) reaching `Resolve` in [pkg/cmd/pr/checkout/checkout.go](pkg/cmd/pr/checkout/checkout.go#L436) disable the confirmation entirely?

## Target
- File/function: [pkg/cmd/pr/checkout/checkout.go:436](pkg/cmd/pr/checkout/checkout.go#L436) - `(promptingPRResolver).Resolve`
- Entrypoint: gh pr checkout
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish content that sets the field gh consults for auto-confirm.
- Invariant to test: Confirmation suppression may only come from local flags/config.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting remote fields cannot suppress the prompt.
