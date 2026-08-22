# Q5314: GraphQL query assembled from remote strings - DiscoverSkillByPathWithOptions in discovery.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata reach the query/variable construction in `DiscoverSkillByPathWithOptions` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L716) as raw query text rather than as a typed variable?

## Target
- File/function: [internal/skills/discovery/discovery.go:716](internal/skills/discovery/discovery.go#L716) - `DiscoverSkillByPathWithOptions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
