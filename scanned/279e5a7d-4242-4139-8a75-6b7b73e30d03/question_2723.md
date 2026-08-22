# Q2723: check run / workflow output rendered raw - printSummary in output.go

## Question
Can check names, annotations, or job output rendered by `printSummary` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L69) - all writable from a fork PR by an unprivileged contributor - carry terminal control sequences?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:69](pkg/cmd/pr/checks/output.go#L69) - `printSummary`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open a PR that runs a workflow emitting the payload into check output.
- Invariant to test: Check-derived text is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with hostile check fixtures.
