# Q1287: sanitizer applied inconsistently - PrCheckStatusSummaryWithColor in display.go

## Question
Is there a branch in `PrCheckStatusSummaryWithColor` in [pkg/cmd/pr/shared/display.go](pkg/cmd/pr/shared/display.go#L85) (non-TTY, --json, pager, error path, markdown fallback) that bypasses the sanitizer the main path uses?

## Target
- File/function: [pkg/cmd/pr/shared/display.go:85](pkg/cmd/pr/shared/display.go#L85) - `PrCheckStatusSummaryWithColor`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Trigger that branch by publishing content that fails the primary render.
- Invariant to test: Sanitization is applied at the write boundary so every branch inherits it.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test each branch asserting sanitized output.
