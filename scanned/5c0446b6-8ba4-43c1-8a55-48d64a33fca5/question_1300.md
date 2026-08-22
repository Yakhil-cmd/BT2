# Q1300: terminal state not restored - parseFile in browse.go

## Question
Can remote content rendered by `parseFile` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L302) leave the victim's terminal in an altered mode (alt screen, mouse reporting, echo off) that persists after gh exits?

## Target
- File/function: [pkg/cmd/browse/browse.go:302](pkg/cmd/browse/browse.go#L302) - `parseFile`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content that switches modes without restoring.
- Invariant to test: gh restores terminal state and strips mode-changing sequences.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting no mode-changing sequences reach the output.
