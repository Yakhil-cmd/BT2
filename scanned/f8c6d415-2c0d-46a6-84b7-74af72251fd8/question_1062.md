# Q1062: markdown renderer emits raw escapes - printPreInstallDisclaimer in install.go

## Question
Does the markdown/HTML path in `printPreInstallDisclaimer` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1189) pass through raw ANSI or hyperlink targets embedded in attacker markdown (code fences, autolinks, reference links)?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1189](pkg/cmd/skills/install/install.go#L1189) - `printPreInstallDisclaimer`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a README/issue body containing escapes inside a code fence and view it with gh skills install.
- Invariant to test: Sanitization happens after rendering, on the final byte stream.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile markdown fixture.
