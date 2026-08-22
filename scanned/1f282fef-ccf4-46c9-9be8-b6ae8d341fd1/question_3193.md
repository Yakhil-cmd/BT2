# Q3193: confirmation skipped when non-interactive - skillSearchFunc in install.go

## Question
Does `skillSearchFunc` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L844) skip its confirmation when stdout is not a TTY or `--yes`-style defaults apply, so an attacker-published object gets a destructive/trusting action in CI?

## Target
- File/function: [pkg/cmd/skills/install/install.go:844](pkg/cmd/skills/install/install.go#L844) - `skillSearchFunc`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Get the victim's automation to run gh skills install against attacker coordinates.
- Invariant to test: Non-interactive mode fails closed instead of auto-confirming.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a non-TTY IOStreams asserting an error rather than a silent yes.
