# Q4231: GraphQL query assembled from remote strings - NewApp in common.go

## Question
Can codespace/API response fields and everything the codespace-side process sends back reach the query/variable construction in `NewApp` in [pkg/cmd/codespace/common.go](pkg/cmd/codespace/common.go#L40) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/codespace/common.go:40](pkg/cmd/codespace/common.go#L40) - `NewApp`
- Entrypoint: gh codespace common
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
