# Q3420: error body echoed verbatim - NewCmdView in view.go

## Question
Does the error construction in `NewCmdView` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L42) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/issue/view/view.go:42](pkg/cmd/issue/view/view.go#L42) - `NewCmdView`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
