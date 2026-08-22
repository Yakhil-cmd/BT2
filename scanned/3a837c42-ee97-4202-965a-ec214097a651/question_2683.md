# Q2683: check run / workflow output rendered raw - Test in iostreams.go

## Question
Can check names, annotations, or job output rendered by `Test` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L585) - all writable from a fork PR by an unprivileged contributor - carry terminal control sequences?

## Target
- File/function: [pkg/iostreams/iostreams.go:585](pkg/iostreams/iostreams.go#L585) - `Test`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Open a PR that runs a workflow emitting the payload into check output.
- Invariant to test: Check-derived text is sanitized.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with hostile check fixtures.
