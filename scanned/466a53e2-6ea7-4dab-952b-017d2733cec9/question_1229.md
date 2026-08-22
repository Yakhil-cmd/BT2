# Q1229: log/artifact rendering after download - getFilesToAdd in edit.go

## Question
Does the content fetched by `getFilesToAdd` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L420) get printed to the terminal without sanitization (workflow logs, gist bodies, file contents an attacker committed)?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:420](pkg/cmd/gist/edit/edit.go#L420) - `getFilesToAdd`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content with control sequences and let the victim view it.
- Invariant to test: All fetched content is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with a hostile fixture.
