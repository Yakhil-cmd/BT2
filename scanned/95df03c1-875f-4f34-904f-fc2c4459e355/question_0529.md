# Q0529: sanitizer applied inconsistently - (IOStreams).StartPager in iostreams.go

## Question
Is there a branch in `StartPager` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L216) (non-TTY, --json, pager, error path, markdown fallback) that bypasses the sanitizer the main path uses?

## Target
- File/function: [pkg/iostreams/iostreams.go:216](pkg/iostreams/iostreams.go#L216) - `(IOStreams).StartPager`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Trigger that branch by publishing content that fails the primary render.
- Invariant to test: Sanitization is applied at the write boundary so every branch inherits it.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test each branch asserting sanitized output.
