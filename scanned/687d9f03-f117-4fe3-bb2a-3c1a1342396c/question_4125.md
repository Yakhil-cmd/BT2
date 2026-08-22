# Q4125: very large field stalls or exhausts the client - NewCmdView in view.go

## Question
Does `NewCmdView` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L40) render an unbounded remote field (huge body, thousands of comments, enormous table cell) without limits?

## Target
- File/function: [pkg/cmd/pr/view/view.go:40](pkg/cmd/pr/view/view.go#L40) - `NewCmdView`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with a multi-megabyte field.
- Invariant to test: Rendering is bounded and streams.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an oversized fixture asserting bounded memory/time.
