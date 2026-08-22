# Q5373: confirmation skipped when non-interactive - runPublishRelease in publish.go

## Question
Does `runPublishRelease` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L481) skip its confirmation when stdout is not a TTY or `--yes`-style defaults apply, so an attacker-published object gets a destructive/trusting action in CI?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:481](pkg/cmd/skills/publish/publish.go#L481) - `runPublishRelease`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Get the victim's automation to run gh skills publish against attacker coordinates.
- Invariant to test: Non-interactive mode fails closed instead of auto-confirming.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a non-TTY IOStreams asserting an error rather than a silent yes.
