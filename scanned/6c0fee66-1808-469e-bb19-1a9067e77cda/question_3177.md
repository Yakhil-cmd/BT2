# Q3177: unauthenticated fallback on error - walkTree in discovery.go

## Question
When authentication fails inside `walkTree` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L881), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [internal/skills/discovery/discovery.go:881](internal/skills/discovery/discovery.go#L881) - `walkTree`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
