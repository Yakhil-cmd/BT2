# Q1771: confirmation skipped when non-interactive - checkOverwrite in install.go

## Question
Does `checkOverwrite` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1045) skip its confirmation when stdout is not a TTY or `--yes`-style defaults apply, so an attacker-published object gets a destructive/trusting action in CI?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1045](pkg/cmd/skills/install/install.go#L1045) - `checkOverwrite`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Get the victim's automation to run gh skills install against attacker coordinates.
- Invariant to test: Non-interactive mode fails closed instead of auto-confirming.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a non-TTY IOStreams asserting an error rather than a silent yes.
