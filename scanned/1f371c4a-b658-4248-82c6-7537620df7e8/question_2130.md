# Q2130: GraphQL query assembled from remote strings - mapRepoNamesToIDs in set.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes reach the query/variable construction in `mapRepoNamesToIDs` in [pkg/cmd/secret/set/set.go](pkg/cmd/secret/set/set.go#L435) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/secret/set/set.go:435](pkg/cmd/secret/set/set.go#L435) - `mapRepoNamesToIDs`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
