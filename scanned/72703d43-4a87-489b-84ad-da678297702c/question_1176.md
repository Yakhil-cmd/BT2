# Q1176: markdown renderer emits raw escapes - printVerifiedSubjects in verify.go

## Question
Does the markdown/HTML path in `printVerifiedSubjects` in [pkg/cmd/release/verify/verify.go](pkg/cmd/release/verify/verify.go#L196) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/release/verify/verify.go:196](pkg/cmd/release/verify/verify.go#L196) - `printVerifiedSubjects`
- Entrypoint: gh release verify
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh release verify.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
