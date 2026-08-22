# Q4550: truncation hides the security-relevant part - NewCmdExtension in extension.go

## Question
Does `NewCmdExtension` in [pkg/cmd/root/extension.go](pkg/cmd/root/extension.go#L22) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [pkg/cmd/root/extension.go:22](pkg/cmd/root/extension.go#L22) - `NewCmdExtension`
- Entrypoint: gh root extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
