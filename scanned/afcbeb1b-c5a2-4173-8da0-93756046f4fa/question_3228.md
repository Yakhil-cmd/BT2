# Q3228: markdown renderer emits raw escapes - printTree in preview.go

## Question
Does the markdown/HTML path in `printTree` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L541) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:541](pkg/cmd/skills/preview/preview.go#L541) - `printTree`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh skills preview.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
