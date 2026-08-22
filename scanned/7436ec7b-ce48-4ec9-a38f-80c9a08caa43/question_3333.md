# Q3333: GraphQL query assembled from remote strings - downloadRun in download.go

## Question
Can an asset, artifact, gist, or archive-member name and its bytes reach the query/variable construction in `downloadRun` in [pkg/cmd/release/download/download.go](pkg/cmd/release/download/download.go#L142) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/release/download/download.go:142](pkg/cmd/release/download/download.go#L142) - `downloadRun`
- Entrypoint: gh release download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
