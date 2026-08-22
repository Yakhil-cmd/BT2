# Q3558: error body echoed verbatim - mapRepoNamesToIDs in set.go

## Question
Does the error construction in `mapRepoNamesToIDs` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L435) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/secret/set/set.go:435](pkg/cmd/secret/set/set.go#L435) - `mapRepoNamesToIDs`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
