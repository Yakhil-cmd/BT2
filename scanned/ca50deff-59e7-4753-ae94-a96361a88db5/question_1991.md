# Q1991: check run / workflow output rendered raw - prProjectList in view.go

## Question
Can check names, annotations, or job output rendered by `prProjectList` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L441) - all writable from a fork PR by an unprivileged contributor - carry terminal control sequences?

## Target
- File/function: [pkg/cmd/pr/view/view.go:441](pkg/cmd/pr/view/view.go#L441) - `prProjectList`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open a PR that runs a workflow emitting the payload into check output.
- Invariant to test: Check-derived text is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with hostile check fixtures.
