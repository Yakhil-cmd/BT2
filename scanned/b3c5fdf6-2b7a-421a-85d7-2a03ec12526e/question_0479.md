# Q0479: error body echoed verbatim - downloadAsset in download.go

## Question
Does the error construction in `downloadAsset` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L300) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/release/download/download.go:300](pkg/cmd/release/download/download.go#L300) - `downloadAsset`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
