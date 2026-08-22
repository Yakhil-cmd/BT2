# Q3946: GraphQL query assembled from remote strings - fetchTags in publish.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata reach the query/variable construction in `fetchTags` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L464) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:464](pkg/cmd/skills/publish/publish.go#L464) - `fetchTags`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
