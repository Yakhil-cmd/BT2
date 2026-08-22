# Q1298: GraphQL query assembled from remote strings - runBrowse in browse.go

## Question
Can an issue/PR title, body, comment, check output, or release note the attacker authored reach the query/variable construction in `runBrowse` in [pkg/cmd/browse/browse.go](pkg/cmd/browse/browse.go#L187) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/browse/browse.go:187](pkg/cmd/browse/browse.go#L187) - `runBrowse`
- Entrypoint: gh browse browse
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
