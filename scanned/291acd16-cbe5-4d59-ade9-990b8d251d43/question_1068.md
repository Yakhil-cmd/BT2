# Q1068: truncation hides the security-relevant part - updateRun in update.go

## Question
Does `updateRun` in [pkg/cmd/skills/update/update.go](pkg/cmd/skills/update/update.go#L143) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [pkg/cmd/skills/update/update.go:143](pkg/cmd/skills/update/update.go#L143) - `updateRun`
- Entrypoint: gh skills update
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
