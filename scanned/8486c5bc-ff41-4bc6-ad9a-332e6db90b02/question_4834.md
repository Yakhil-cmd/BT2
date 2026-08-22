# Q4834: very large field stalls or exhausts the client - FormatSize in text.go

## Question
Does `FormatSize` in [internal/text/text.go](internal/text/text.go#L156) render an unbounded remote field (huge body, thousands of comments, enormous table cell) without limits?

## Target
- File/function: [internal/text/text.go:156](internal/text/text.go#L156) - `FormatSize`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with a multi-megabyte field.
- Invariant to test: Rendering is bounded and streams.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an oversized fixture asserting bounded memory/time.
