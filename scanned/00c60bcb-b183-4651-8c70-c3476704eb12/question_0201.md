# Q0201: host-scoped client leaked into another flow - preloadPrComments in finder.go

## Question
Can the client/transport constructed in `preloadPrComments` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L484) (with its auth round-tripper) be reused by a later flow whose target host came from a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:484](pkg/cmd/pr/shared/finder.go#L484) - `preloadPrComments`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
