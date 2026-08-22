# Q5980: confirmation skipped when non-interactive - promptForSkillOrigin in update.go

## Question
Does `promptForSkillOrigin` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L643) skip its confirmation when stdout is not a TTY or `--yes`-style defaults apply, so an attacker-published object gets a destructive/trusting action in CI?

## Target
- File/function: [pkg/cmd/skills/update/update.go:643](pkg/cmd/skills/update/update.go#L643) - `promptForSkillOrigin`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Get the victim's automation to run gh skills update against attacker coordinates.
- Invariant to test: Non-interactive mode fails closed instead of auto-confirming.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a non-TTY IOStreams asserting an error rather than a silent yes.
