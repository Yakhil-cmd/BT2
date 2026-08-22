# Q1865: truncation hides the security-relevant part - (LiveClient).getTrustDomain in client.go

## Question
Does `getTrustDomain` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L303) truncate or column-fit remote text such that a host, URL, or repo name shown for a trust decision is cut, letting a lookalike be mistaken for the real one?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:303](pkg/cmd/attestation/api/client.go#L303) - `(LiveClient).getTrustDomain`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Use a very long owner/host prefix so the visible portion reads as github.com.
- Invariant to test: Security-relevant identifiers are never elided; they are shown in full or the action aborts.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test with a long hostile name asserting the full identifier appears.
