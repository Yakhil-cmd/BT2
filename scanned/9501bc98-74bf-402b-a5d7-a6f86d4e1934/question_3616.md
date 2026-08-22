# Q3616: GraphQL query assembled from remote strings - getViewer in flow.go

## Question
Can a hostname, OAuth/device response, or git credential-protocol input the attacker supplies reach the query/variable construction in `getViewer` in [internal/authflow/flow.go](internal/authflow/flow.go#L126) as raw query text rather than as a typed variable?

## Target
- File/function: [internal/authflow/flow.go:126](internal/authflow/flow.go#L126) - `getViewer`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
