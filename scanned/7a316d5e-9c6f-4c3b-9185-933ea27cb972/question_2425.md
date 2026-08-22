# Q2425: markdown renderer emits raw escapes - printArgs in run.go

## Question
Does the markdown/HTML path in `printArgs` in [internal/run/run.go](internal/run/run.go#L91) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [internal/run/run.go:91](internal/run/run.go#L91) - `printArgs`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh extension install.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
