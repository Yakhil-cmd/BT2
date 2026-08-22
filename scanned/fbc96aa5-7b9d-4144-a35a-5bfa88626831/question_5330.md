# Q5330: prompt bypassed by config/flag from remote content - selectSkillsWithSelector in install.go

## Question
Can a value originating in remote content (skill/extension/codespace metadata) reaching `selectSkillsWithSelector` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L698) disable the confirmation entirely?

## Target
- File/function: [pkg/cmd/skills/install/install.go:698](pkg/cmd/skills/install/install.go#L698) - `selectSkillsWithSelector`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish content that sets the field gh consults for auto-confirm.
- Invariant to test: Confirmation suppression may only come from local flags/config.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting remote fields cannot suppress the prompt.
