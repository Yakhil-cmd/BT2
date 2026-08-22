# Q1994: terminal state not restored - printRawIssuePreview in view.go

## Question
Can remote content rendered by `printRawIssuePreview` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L197) leave the victim's terminal in an altered mode (alt screen, mouse reporting, echo off) that persists after gh exits?

## Target
- File/function: [pkg/cmd/issue/view/view.go:197](pkg/cmd/issue/view/view.go#L197) - `printRawIssuePreview`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content that switches modes without restoring.
- Invariant to test: gh restores terminal state and strips mode-changing sequences.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting no mode-changing sequences reach the output.
