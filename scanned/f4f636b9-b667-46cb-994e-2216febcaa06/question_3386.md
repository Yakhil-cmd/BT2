# Q3386: markdown renderer emits raw escapes - (IOStreams).StopPager in iostreams.go

## Question
Does the markdown/HTML path in `StopPager` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L264) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/iostreams/iostreams.go:264](pkg/iostreams/iostreams.go#L264) - `(IOStreams).StopPager`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh pr view.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
