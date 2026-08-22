# Q2727: very large field stalls or exhausts the client - parseSection in browse.go

## Question
Does `parseSection` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L230) render an unbounded remote field (huge body, thousands of comments, enormous table cell) without limits?

## Target
- File/function: [pkg/cmd/browse/browse.go:230](pkg/cmd/browse/browse.go#L230) - `parseSection`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with a multi-megabyte field.
- Invariant to test: Rendering is bounded and streams.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an oversized fixture asserting bounded memory/time.
