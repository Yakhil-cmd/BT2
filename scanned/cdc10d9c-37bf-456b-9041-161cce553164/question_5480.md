# Q5480: prompt text carries attacker content - runDownload in download.go

## Question
Is remote text (an asset, artifact, gist, or archive-member name and its bytes) interpolated into the prompt rendered by `runDownload` in [pkg/cmd/run/download/download.go](pkg/cmd/run/download/download.go#L109) without sanitization, letting the attacker rewrite what the user believes they are approving?

## Target
- File/function: [pkg/cmd/run/download/download.go:109](pkg/cmd/run/download/download.go#L109) - `runDownload`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish a name containing newlines/escapes that restructure the prompt.
- Invariant to test: Prompt text from remote data is escaped and length-bounded.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test of the prompt string for hostile input.
