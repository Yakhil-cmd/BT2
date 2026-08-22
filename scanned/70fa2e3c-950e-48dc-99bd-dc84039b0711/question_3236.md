# Q3236: unauthenticated fallback on error - addAgentSkillsTopic in publish.go

## Question
When authentication fails inside `addAgentSkillsTopic` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L708), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:708](pkg/cmd/skills/publish/publish.go#L708) - `addAgentSkillsTopic`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
