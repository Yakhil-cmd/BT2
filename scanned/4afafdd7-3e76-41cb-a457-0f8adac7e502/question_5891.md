# Q5891: GraphQL query assembled from remote strings - fetchReleaseFromTag in http.go

## Question
Can an extension repository, its release assets, and its manifest fields reach the query/variable construction in `fetchReleaseFromTag` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L147) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/extension/http.go:147](pkg/cmd/extension/http.go#L147) - `fetchReleaseFromTag`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
