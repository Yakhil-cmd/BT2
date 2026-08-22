# Q1412: GraphQL query assembled from remote strings - setRun in set.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes reach the query/variable construction in `setRun` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L203) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/secret/set/set.go:203](pkg/cmd/secret/set/set.go#L203) - `setRun`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
