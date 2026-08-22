# Q2661: truncation hides the security-relevant part - createRun in create.go

## Question
Does `createRun` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L108) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [pkg/cmd/gist/create/create.go:108](pkg/cmd/gist/create/create.go#L108) - `createRun`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
