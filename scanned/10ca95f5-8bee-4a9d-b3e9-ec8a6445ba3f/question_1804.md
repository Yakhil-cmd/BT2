# Q1804: host-scoped client leaked into another flow - fetchTags in publish.go

## Question
Can the client/transport constructed in `fetchTags` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L464) (with its auth round-tripper) be reused by a later flow whose target host came from a published skill's archive entries, frontmatter, and registry metadata?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:464](pkg/cmd/skills/publish/publish.go#L464) - `fetchTags`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Chain two operations where the second targets an attacker host.
- Invariant to test: Auth round-trippers verify the request host on every call.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test reusing the client against a foreign host asserting the header is dropped.
