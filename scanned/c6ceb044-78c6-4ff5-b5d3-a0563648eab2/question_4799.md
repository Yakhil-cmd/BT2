# Q4799: log/artifact rendering after download - NewCmdView in view.go

## Question
Does the content fetched by `NewCmdView` in [pkg/cmd/gist/view/view.go](pkg/cmd/gist/view/view.go#L42) get printed to the terminal without sanitization (workflow logs, gist bodies, file contents an attacker committed)?

## Target
- File/function: [pkg/cmd/gist/view/view.go:42](pkg/cmd/gist/view/view.go#L42) - `NewCmdView`
- Entrypoint: gh gist view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish content with control sequences and let the victim view it.
- Invariant to test: All fetched content is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test with a hostile fixture.
