# Q4918: truncation hides the security-relevant part - (API).EditCodespace in api.go

## Question
Does `EditCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1162) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [internal/codespaces/api/api.go:1162](internal/codespaces/api/api.go#L1162) - `(API).EditCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
