# Q2416: truncation hides the security-relevant part - printError in cmd.go

## Question
Does `printError` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L282) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [internal/ghcmd/cmd.go:282](internal/ghcmd/cmd.go#L282) - `printError`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
