# Q0586: sanitizer applied inconsistently - parseFile in browse.go

## Question
Is there a branch in `parseFile` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L302) (non-TTY, --json, pager, error path, markdown fallback) that bypasses the sanitizer the main path uses?

## Target
- File/function: [pkg/cmd/browse/browse.go:302](pkg/cmd/browse/browse.go#L302) - `parseFile`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Trigger that branch by publishing content that fails the primary render.
- Invariant to test: Sanitization is applied at the write boundary so every branch inherits it.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test each branch asserting sanitized output.
