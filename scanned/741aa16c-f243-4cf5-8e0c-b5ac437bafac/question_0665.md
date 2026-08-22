# Q0665: host-scoped client leaked into another flow - (codespace).running in common.go

## Question
Can the client/transport constructed in `running` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L231) (with its auth round-tripper) be reused by a later flow whose target host came from codespace/API response fields and everything the codespace-side process sends back?

## Target
- File/function: [pkg/cmd/codespace/common.go:231](pkg/cmd/codespace/common.go#L231) - `(codespace).running`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
