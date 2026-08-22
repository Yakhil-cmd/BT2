# Q5573: very large field stalls or exhausts the client - formatComment in comments.go

## Question
Does `formatComment` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L89) render an unbounded remote field (huge body, thousands of comments, enormous table cell) without limits?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:89](pkg/cmd/pr/shared/comments.go#L89) - `formatComment`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with a multi-megabyte field.
- Invariant to test: Rendering is bounded and streams.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an oversized fixture asserting bounded memory/time.
