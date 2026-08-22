# Q2507: GraphQL query assembled from remote strings - renderInteractive in preview.go

## Question
Can a published skill's archive entries, frontmatter, and registry metadata reach the query/variable construction in `renderInteractive` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L318) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:318](pkg/cmd/skills/preview/preview.go#L318) - `renderInteractive`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
