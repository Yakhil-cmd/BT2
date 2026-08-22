# Q2813: GraphQL query assembled from remote strings - CapiClientFunc in capi.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes reach the query/variable construction in `CapiClientFunc` in [pkg/cmd/agent-task/shared/capi.go](pkg/cmd/agent-task/shared/capi.go#L21) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/agent-task/shared/capi.go:21](pkg/cmd/agent-task/shared/capi.go#L21) - `CapiClientFunc`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
