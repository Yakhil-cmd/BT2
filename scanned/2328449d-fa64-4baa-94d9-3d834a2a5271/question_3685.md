# Q3685: truncation hides the security-relevant part - externalHttpClientFunc in default.go

## Question
Does `externalHttpClientFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L230) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [pkg/cmd/factory/default.go:230](pkg/cmd/factory/default.go#L230) - `externalHttpClientFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
