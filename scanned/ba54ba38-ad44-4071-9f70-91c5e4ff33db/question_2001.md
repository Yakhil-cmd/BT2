# Q2001: terminal state not restored - PrCheckStatusSummaryWithColor in display.go

## Question
Can remote content rendered by `PrCheckStatusSummaryWithColor` in [pkg/cmd/pr/shared/display.go](pkg/cmd/pr/shared/display.go#L85) leave the victim's terminal in an altered mode (alt screen, mouse reporting, echo off) that persists after gh exits?

## Target
- File/function: [pkg/cmd/pr/shared/display.go:85](pkg/cmd/pr/shared/display.go#L85) - `PrCheckStatusSummaryWithColor`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content that switches modes without restoring.
- Invariant to test: gh restores terminal state and strips mode-changing sequences.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting no mode-changing sequences reach the output.
