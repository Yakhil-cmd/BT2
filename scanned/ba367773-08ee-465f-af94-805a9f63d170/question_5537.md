# Q5537: very large field stalls or exhausts the client - Test in iostreams.go

## Question
Does `Test` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L585) render an unbounded remote field (huge body, thousands of comments, enormous table cell) without limits?

## Target
- File/function: [pkg/iostreams/iostreams.go:585](pkg/iostreams/iostreams.go#L585) - `Test`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with a multi-megabyte field.
- Invariant to test: Rendering is bounded and streams.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an oversized fixture asserting bounded memory/time.
