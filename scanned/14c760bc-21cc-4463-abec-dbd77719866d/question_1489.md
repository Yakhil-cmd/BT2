# Q1489: missing timeout enables hang - helperRun in helper.go

## Question
Does the request path in `helperRun` in [pkg/cmd/auth/gitcredential/helper.go](pkg/cmd/auth/gitcredential/helper.go#L58) run without a timeout/context deadline so an attacker-controlled endpoint can hang the victim's gh indefinitely (including in CI)?

## Target
- File/function: [pkg/cmd/auth/gitcredential/helper.go:58](pkg/cmd/auth/gitcredential/helper.go#L58) - `helperRun`
- Entrypoint: gh auth gitcredential
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Serve a slow-loris response from the host the victim's gh talks to.
- Invariant to test: Every outbound request carries a bounded timeout.
- Expected Immunefi impact: High - Unbounded resource consumption on the victim's machine from a single attacker-published object
- Fast validation: Test with a stalling server asserting the call returns within the deadline.
