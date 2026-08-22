# Q3439: check run / workflow output rendered raw - NewCmdBrowse in browse.go

## Question
Can check names, annotations, or job output rendered by `NewCmdBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L52) - all writable from a fork PR by an unprivileged contributor - carry terminal control sequences?

## Target
- File/function: [pkg/cmd/browse/browse.go:52](pkg/cmd/browse/browse.go#L52) - `NewCmdBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open a PR that runs a workflow emitting the payload into check output.
- Invariant to test: Check-derived text is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with hostile check fixtures.
