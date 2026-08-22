# Q0484: log/artifact rendering after download - runDownload in download.go

## Question
Does the content fetched by `runDownload` in [pkg/cmd/run/download/download.go](pkg/cmd/run/download/download.go#L109) get printed to the terminal without sanitization (workflow logs, gist bodies, file contents an attacker committed)?

## Target
- File/function: [pkg/cmd/run/download/download.go:109](pkg/cmd/run/download/download.go#L109) - `runDownload`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content with control sequences and let the victim view it.
- Invariant to test: All fetched content is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with a hostile fixture.
