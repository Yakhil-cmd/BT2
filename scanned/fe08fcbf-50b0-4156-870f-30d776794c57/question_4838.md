# Q4838: sanitizer applied inconsistently - NewCmdView in view.go

## Question
Is there a branch in `NewCmdView` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L40) (non-TTY, --json, pager, error path, markdown fallback) that bypasses the sanitizer the main path uses?

## Target
- File/function: [pkg/cmd/pr/view/view.go:40](pkg/cmd/pr/view/view.go#L40) - `NewCmdView`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Trigger that branch by publishing content that fails the primary render.
- Invariant to test: Sanitization is applied at the write boundary so every branch inherits it.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test each branch asserting sanitized output.
