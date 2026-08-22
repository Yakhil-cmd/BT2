# Q3940: confirmation skipped when non-interactive - selectSkill in preview.go

## Question
Does `selectSkill` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L453) skip its confirmation when stdout is not a TTY or `--yes`-style defaults apply, so an attacker-published object gets a destructive/trusting action in CI?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:453](pkg/cmd/skills/preview/preview.go#L453) - `selectSkill`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Get the victim's automation to run gh skills preview against attacker coordinates.
- Invariant to test: Non-interactive mode fails closed instead of auto-confirming.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a non-TTY IOStreams asserting an error rather than a silent yes.
