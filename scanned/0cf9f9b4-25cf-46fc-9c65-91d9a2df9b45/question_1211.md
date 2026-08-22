# Q1211: log/artifact rendering after download - ExtractZip in zip.go

## Question
Does the content fetched by `ExtractZip` in [internal/zip/zip.go](internal/zip/zip.go#L24) get printed to the terminal without sanitization (workflow logs, gist bodies, file contents an attacker committed)?

## Target
- File/function: [internal/zip/zip.go:24](internal/zip/zip.go#L24) - `ExtractZip`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content with control sequences and let the victim view it.
- Invariant to test: All fetched content is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with a hostile fixture.
