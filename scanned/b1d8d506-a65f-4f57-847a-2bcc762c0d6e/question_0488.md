# Q0488: GraphQL query assembled from remote strings - (apiLogFetcher).GetLog in logs.go

## Question
Can an asset, artifact, gist, or archive-member name and its bytes reach the query/variable construction in `GetLog` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L42) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/run/view/logs.go:42](pkg/cmd/run/view/logs.go#L42) - `(apiLogFetcher).GetLog`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
