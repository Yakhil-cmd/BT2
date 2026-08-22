# Q4753: error body echoed verbatim - FetchLatestRelease in fetch.go

## Question
Does the error construction in `FetchLatestRelease` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L237) embed the attacker-controlled response body or headers into a message that is printed or sent to telemetry?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:237](pkg/cmd/release/shared/fetch.go#L237) - `FetchLatestRelease`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Return an error body containing escapes or fabricated gh output.
- Invariant to test: Server-supplied error text is sanitized and length-bounded before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the error string for a hostile body.
