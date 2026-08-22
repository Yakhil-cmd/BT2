# Q4767: confirmation skipped when non-interactive - runDownload in download.go

## Question
Does `runDownload` in [pkg/cmd/run/download/download.go](pkg/cmd/run/download/download.go#L109) skip its confirmation when stdout is not a TTY or `--yes`-style defaults apply, so an attacker-published object gets a destructive/trusting action in CI?

## Target
- File/function: [pkg/cmd/run/download/download.go:109](pkg/cmd/run/download/download.go#L109) - `runDownload`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Get the victim's automation to run gh run download against attacker coordinates.
- Invariant to test: Non-interactive mode fails closed instead of auto-confirming.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a non-TTY IOStreams asserting an error rather than a silent yes.
