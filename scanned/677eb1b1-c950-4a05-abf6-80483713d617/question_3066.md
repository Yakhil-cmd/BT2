# Q3066: error body echoed verbatim - developRunList in develop.go

## Question
Does the error construction in `developRunList` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L319) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:319](pkg/cmd/issue/develop/develop.go#L319) - `developRunList`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
