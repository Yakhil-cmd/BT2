# Q5484: markdown renderer emits raw escapes - (apiLogFetcher).GetLog in logs.go

## Question
Does the markdown/HTML path in `GetLog` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L42) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/run/view/logs.go:42](pkg/cmd/run/view/logs.go#L42) - `(apiLogFetcher).GetLog`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh run view.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
