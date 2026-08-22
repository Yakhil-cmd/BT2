# Q5576: terminal state not restored - addRow in output.go

## Question
Can remote content rendered by `addRow` in [pkg/cmd/pr/checks/output.go](pkg/cmd/pr/checks/output.go#L11) leave the victim's terminal in an altered mode (alt screen, mouse reporting, echo off) that persists after gh exits?

## Target
- File/function: [pkg/cmd/pr/checks/output.go:11](pkg/cmd/pr/checks/output.go#L11) - `addRow`
- Entrypoint: gh pr checks
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content that switches modes without restoring.
- Invariant to test: gh restores terminal state and strips mode-changing sequences.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting no mode-changing sequences reach the output.
