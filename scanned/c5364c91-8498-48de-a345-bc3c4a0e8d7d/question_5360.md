# Q5360: error body echoed verbatim - renderAllFiles in preview.go

## Question
Does the error construction in `renderAllFiles` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L267) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:267](pkg/cmd/skills/preview/preview.go#L267) - `renderAllFiles`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
