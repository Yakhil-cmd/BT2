# Q0566: very large field stalls or exhausts the client - printRawIssuePreview in view.go

## Question
Does `printRawIssuePreview` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L197) render an unbounded remote field (huge body, thousands of comments, enormous table cell) without limits?

## Target
- File/function: [pkg/cmd/issue/view/view.go:197](pkg/cmd/issue/view/view.go#L197) - `printRawIssuePreview`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object with a multi-megabyte field.
- Invariant to test: Rendering is bounded and streams.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with an oversized fixture asserting bounded memory/time.
