# Q0556: truncation hides the security-relevant part - viewRun in view.go

## Question
Does `viewRun` in [pkg/cmd/pr/view/view.go](pkg/cmd/pr/view/view.go#L92) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [pkg/cmd/pr/view/view.go:92](pkg/cmd/pr/view/view.go#L92) - `viewRun`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
