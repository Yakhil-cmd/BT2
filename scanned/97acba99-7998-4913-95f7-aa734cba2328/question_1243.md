# Q1243: terminal state not restored - (IOStreams).StartPager in iostreams.go

## Question
Can remote content rendered by `StartPager` in [pkg/iostreams/iostreams.go](pkg/iostreams/iostreams.go#L216) leave the victim's terminal in an altered mode (alt screen, mouse reporting, echo off) that persists after gh exits?

## Target
- File/function: [pkg/iostreams/iostreams.go:216](pkg/iostreams/iostreams.go#L216) - `(IOStreams).StartPager`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish content that switches modes without restoring.
- Invariant to test: gh restores terminal state and strips mode-changing sequences.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting no mode-changing sequences reach the output.
