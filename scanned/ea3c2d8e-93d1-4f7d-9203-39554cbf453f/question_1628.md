# Q1628: error body echoed verbatim - preloadPrReviews in finder.go

## Question
Does the error construction in `preloadPrReviews` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L444) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:444](pkg/cmd/pr/shared/finder.go#L444) - `preloadPrReviews`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
