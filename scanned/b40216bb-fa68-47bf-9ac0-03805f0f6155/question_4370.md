# Q4370: markdown renderer emits raw escapes - ExtractHeader in http_client.go

## Question
Does the markdown/HTML path in `ExtractHeader` in [api/http_client.go](api/http_client.go#L175) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [api/http_client.go:175](api/http_client.go#L175) - `ExtractHeader`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...).
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
