# Q2729: error body echoed verbatim - (remoteGitClient).LastCommit in browse.go

## Question
Does the error construction in `LastCommit` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L375) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/browse/browse.go:375](pkg/cmd/browse/browse.go#L375) - `(remoteGitClient).LastCommit`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
