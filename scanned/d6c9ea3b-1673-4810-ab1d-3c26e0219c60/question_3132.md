# Q3132: GraphQL query assembled from remote strings - checkForUpdate in cmd.go

## Question
Can an extension repository, its release assets, and its manifest fields reach the query/variable construction in `checkForUpdate` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L318) as raw query text rather than as a typed variable?

## Target
- File/function: [internal/ghcmd/cmd.go:318](internal/ghcmd/cmd.go#L318) - `checkForUpdate`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
