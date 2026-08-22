# Q0543: sanitizer applied inconsistently - CopyGuardedContent in content.go

## Question
Is there a branch in `CopyGuardedContent` in [pkg/iostreams/content.go](pkg/iostreams/content.go#L63) (non-TTY, --json, pager, error path, markdown fallback) that bypasses the sanitizer the main path uses?

## Target
- File/function: [pkg/iostreams/content.go:63](pkg/iostreams/content.go#L63) - `CopyGuardedContent`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Trigger that branch by publishing content that fails the primary render.
- Invariant to test: Sanitization is applied at the write boundary so every branch inherits it.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test each branch asserting sanitized output.
