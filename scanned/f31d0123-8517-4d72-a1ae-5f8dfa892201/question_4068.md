# Q4068: log/artifact rendering after download - extractZipFile in zip.go

## Question
Does the content fetched by `extractZipFile` in [internal/zip/zip.go](internal/zip/zip.go#L42) get printed to the terminal without sanitization (workflow logs, gist bodies, file contents an attacker committed)?

## Target
- File/function: [internal/zip/zip.go:42](internal/zip/zip.go#L42) - `extractZipFile`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content with control sequences and let the victim view it.
- Invariant to test: All fetched content is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with a hostile fixture.
