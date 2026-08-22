# Q0922: host-scoped client leaked into another flow - developRunCreate in develop.go

## Question
Can the client/transport constructed in `developRunCreate` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L201) (with its auth round-tripper) be reused by a later flow whose target host came from a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:201](pkg/cmd/issue/develop/develop.go#L201) - `developRunCreate`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
