# Q2698: auto-open without confirmation - viewRun in view.go

## Question
Does the flow through `viewRun` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L92) open a remote-supplied URL without the user explicitly asking, enabling drive-by navigation from a routine command?

## Target
- File/function: [pkg/cmd/pr/view/view.go:92](pkg/cmd/pr/view/view.go#L92) - `viewRun`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object whose listing/view path triggers the open.
- Invariant to test: Browser launches require an explicit user action or flag.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting no opener call on non-interactive/list paths.
