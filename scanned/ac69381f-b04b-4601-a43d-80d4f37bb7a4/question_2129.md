# Q2129: confirmation skipped when non-interactive - getBody in set.go

## Question
Does `getBody` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L413) skip its confirmation when stdout is not a TTY or `--yes`-style defaults apply, so an attacker-published object gets a destructive/trusting action in CI?

## Target
- File/function: [pkg/cmd/secret/set/set.go:413](pkg/cmd/secret/set/set.go#L413) - `getBody`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Get the victim's automation to run gh secret set against attacker coordinates.
- Invariant to test: Non-interactive mode fails closed instead of auto-confirming.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test with a non-TTY IOStreams asserting an error rather than a silent yes.
