# Q4853: sanitizer applied inconsistently - issueLabelList in view.go

## Question
Is there a branch in `issueLabelList` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L446) (non-TTY, --json, pager, error path, markdown fallback) that bypasses the sanitizer the main path uses?

## Target
- File/function: [pkg/cmd/issue/view/view.go:446](pkg/cmd/issue/view/view.go#L446) - `issueLabelList`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Trigger that branch by publishing content that fails the primary render.
- Invariant to test: Sanitization is applied at the write boundary so every branch inherits it.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test each branch asserting sanitized output.
