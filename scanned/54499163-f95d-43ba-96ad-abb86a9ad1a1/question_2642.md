# Q2642: markdown renderer emits raw escapes - readFileRun in read_file.go

## Question
Does the markdown/HTML path in `readFileRun` in [pkg/cmd/repo/read-file/read_file.go](pkg/cmd/repo/read-file/read_file.go#L128) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/repo/read-file/read_file.go:128](pkg/cmd/repo/read-file/read_file.go#L128) - `readFileRun`
- Entrypoint: gh repo read-file
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh repo read-file.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
