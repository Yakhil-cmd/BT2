# Q1938: host shown differs from host used - PromptGists in shared.go

## Question
Does the confirmation in `PromptGists` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L228) display a host/repo string that is derived differently from the value actually used afterwards?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:228](pkg/cmd/gist/shared/shared.go#L228) - `PromptGists`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish coordinates where display and action diverge (lookalike host, renamed repo).
- Invariant to test: Displayed and acted-on identifiers come from the same variable.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting the prompt string and the executed target are the same value.
