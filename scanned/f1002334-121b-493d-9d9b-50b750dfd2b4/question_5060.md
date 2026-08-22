# Q5060: GraphQL query assembled from remote strings - sshKeyUpload in login_flow.go

## Question
Can a hostname, OAuth/device response, or git credential-protocol input the attacker supplies reach the query/variable construction in `sshKeyUpload` in [pkg/cmd/auth/shared/login_flow.go](pkg/cmd/auth/shared/login_flow.go#L243) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/auth/shared/login_flow.go:243](pkg/cmd/auth/shared/login_flow.go#L243) - `sshKeyUpload`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
