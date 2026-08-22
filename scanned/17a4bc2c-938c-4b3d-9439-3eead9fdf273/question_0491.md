# Q0491: log/artifact rendering after download - getZipLogMap in logs.go

## Question
Does the content fetched by `getZipLogMap` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L221) get printed to the terminal without sanitization (workflow logs, gist bodies, file contents an attacker committed)?

## Target
- File/function: [pkg/cmd/run/view/logs.go:221](pkg/cmd/run/view/logs.go#L221) - `getZipLogMap`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content with control sequences and let the victim view it.
- Invariant to test: All fetched content is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with a hostile fixture.
