# Q2717: markdown renderer emits raw escapes - formatRawComment in comments.go

## Question
Does the markdown/HTML path in `formatRawComment` in [pkg/cmd/pr/shared/comments.go](pkg/cmd/pr/shared/comments.go#L38) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/pr/shared/comments.go:38](pkg/cmd/pr/shared/comments.go#L38) - `formatRawComment`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh pr.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
