# Q4968: GraphQL query assembled from remote strings - downloadCopilot in copilot.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes reach the query/variable construction in `downloadCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L239) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:239](pkg/cmd/copilot/copilot.go#L239) - `downloadCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
