# Q5560: host-scoped client leaked into another flow - NewCmdView in view.go

## Question
Can the client/transport constructed in `NewCmdView` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L42) (with its auth round-tripper) be reused by a later flow whose target host came from an issue/PR title, body, comment, check output, or release note the attacker authored?

## Target
- File/function: [pkg/cmd/issue/view/view.go:42](pkg/cmd/issue/view/view.go#L42) - `NewCmdView`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
