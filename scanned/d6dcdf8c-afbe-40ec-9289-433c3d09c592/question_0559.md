# Q0559: terminal state not restored - formattedReviewerState in view.go

## Question
Can remote content rendered by `formattedReviewerState` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L310) leave the victim's terminal in an altered mode (alt screen, mouse reporting, echo off) that persists after gh exits?

## Target
- File/function: [pkg/cmd/pr/view/view.go:310](pkg/cmd/pr/view/view.go#L310) - `formattedReviewerState`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content that switches modes without restoring.
- Invariant to test: gh restores terminal state and strips mode-changing sequences.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting no mode-changing sequences reach the output.
