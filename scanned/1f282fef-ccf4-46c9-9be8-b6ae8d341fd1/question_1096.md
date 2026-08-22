# Q1096: error body echoed verbatim - enableImmutableReleases in publish.go

## Question
Does the error construction in `enableImmutableReleases` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L754) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:754](pkg/cmd/skills/publish/publish.go#L754) - `enableImmutableReleases`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
