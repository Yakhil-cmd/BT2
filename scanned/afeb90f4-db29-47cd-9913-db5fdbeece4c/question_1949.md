# Q1949: log/artifact rendering after download - guessGistName in create.go

## Question
Does the content fetched by `guessGistName` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L244) get printed to the terminal without sanitization (workflow logs, gist bodies, file contents an attacker committed)?

## Target
- File/function: [pkg/cmd/gist/create/create.go:244](pkg/cmd/gist/create/create.go#L244) - `guessGistName`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content with control sequences and let the victim view it.
- Invariant to test: All fetched content is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with a hostile fixture.
