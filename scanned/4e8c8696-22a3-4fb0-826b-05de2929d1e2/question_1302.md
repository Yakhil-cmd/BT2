# Q1302: auto-open without confirmation - New in browser.go

## Question
Does the flow through `New` in [internal/browser/browser.go](internal/browser/browser.go#L13) open a remote-supplied URL without the user explicitly asking, enabling drive-by navigation from a routine command?

## Target
- File/function: [internal/browser/browser.go:13](internal/browser/browser.go#L13) - `New`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object whose listing/view path triggers the open.
- Invariant to test: Browser launches require an explicit user action or flag.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting no opener call on non-interactive/list paths.
