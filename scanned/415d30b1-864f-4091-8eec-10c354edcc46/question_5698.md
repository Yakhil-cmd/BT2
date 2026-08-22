# Q5698: host-scoped client leaked into another flow - mapRepoNamesToIDs in set.go

## Question
Can the client/transport constructed in `mapRepoNamesToIDs` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L435) (with its auth round-tripper) be reused by a later flow whose target host came from an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes?

## Target
- File/function: [pkg/cmd/secret/set/set.go:435](pkg/cmd/secret/set/set.go#L435) - `mapRepoNamesToIDs`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
