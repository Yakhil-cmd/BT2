# Q2797: GraphQL query assembled from remote strings - (App).ForwardPorts in ports.go

## Question
Can codespace/API response fields and everything the codespace-side process sends back reach the query/variable construction in `ForwardPorts` in [pkg/cmd/codespace/ports.go](pkg/cmd/codespace/ports.go#L324) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/codespace/ports.go:324](pkg/cmd/codespace/ports.go#L324) - `(App).ForwardPorts`
- Entrypoint: gh codespace ports
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
