# Q0392: markdown renderer emits raw escapes - renderDiagnosticsPlain in publish.go

## Question
Does the markdown/HTML path in `renderDiagnosticsPlain` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L1118) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:1118](pkg/cmd/skills/publish/publish.go#L1118) - `renderDiagnosticsPlain`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh skills publish.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
