# Q1647: host-scoped client leaked into another flow - (Manager).list in manager.go

## Question
Can the client/transport constructed in `list` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L150) (with its auth round-tripper) be reused by a later flow whose target host came from an extension repository, its release assets, and its manifest fields?

## Target
- File/function: [pkg/cmd/extension/manager.go:150](pkg/cmd/extension/manager.go#L150) - `(Manager).list`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
