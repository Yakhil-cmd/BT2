# Q4538: pager/child renderer receives raw bytes - downloadAsset in http.go

## Question
Does `downloadAsset` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L79) hand unsanitized remote text to a pager or external renderer where escape handling differs from gh's own?

## Target
- File/function: [pkg/cmd/extension/http.go:79](pkg/cmd/extension/http.go#L79) - `downloadAsset`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish content whose escapes are inert in gh but active in the pager.
- Invariant to test: Sanitization is applied before the bytes leave gh, regardless of the sink.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the bytes written to a stub pager are already sanitized.
