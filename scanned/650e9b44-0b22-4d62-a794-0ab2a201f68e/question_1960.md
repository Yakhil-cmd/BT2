# Q1960: markdown renderer emits raw escapes - (IOStreams).startTextualProgressIndicator in iostreams.go

## Question
Does the markdown/HTML path in `startTextualProgressIndicator` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L342) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/iostreams/iostreams.go:342](pkg/iostreams/iostreams.go#L342) - `(IOStreams).startTextualProgressIndicator`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh pr view.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
