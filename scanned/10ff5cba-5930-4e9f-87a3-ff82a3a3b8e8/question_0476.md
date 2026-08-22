# Q0476: log/artifact rendering after download - checkArchiveTypeOption in download.go

## Question
Does the content fetched by `checkArchiveTypeOption` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L123) get printed to the terminal without sanitization (workflow logs, gist bodies, file contents an attacker committed)?

## Target
- File/function: [pkg/cmd/release/download/download.go:123](pkg/cmd/release/download/download.go#L123) - `checkArchiveTypeOption`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content with control sequences and let the victim view it.
- Invariant to test: All fetched content is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with a hostile fixture.
