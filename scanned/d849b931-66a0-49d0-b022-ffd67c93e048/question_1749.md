# Q1749: error body echoed verbatim - walkTree in discovery.go

## Question
Does the error construction in `walkTree` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L881) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [internal/skills/discovery/discovery.go:881](internal/skills/discovery/discovery.go#L881) - `walkTree`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
