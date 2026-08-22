# Q3676: log/artifact rendering after download - (Absolute).Join in absolute.go

## Question
Does the content fetched by `Join` in [internal/safepaths/absolute.go](internal/safepaths/absolute.go#L38) get printed to the terminal without sanitization (workflow logs, gist bodies, file contents an attacker committed)?

## Target
- File/function: [internal/safepaths/absolute.go:38](internal/safepaths/absolute.go#L38) - `(Absolute).Join`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content with control sequences and let the victim view it.
- Invariant to test: All fetched content is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with a hostile fixture.
