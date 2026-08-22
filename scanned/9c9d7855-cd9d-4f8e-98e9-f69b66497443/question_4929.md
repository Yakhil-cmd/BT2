# Q4929: GraphQL query assembled from remote strings - (App).printOpenSSHConfig in ssh.go

## Question
Can codespace/API response fields and everything the codespace-side process sends back reach the query/variable construction in `printOpenSSHConfig` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L552) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:552](pkg/cmd/codespace/ssh.go#L552) - `(App).printOpenSSHConfig`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
