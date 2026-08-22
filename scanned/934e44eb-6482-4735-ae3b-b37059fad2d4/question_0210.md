# Q0210: GraphQL query assembled from remote strings - developRunList in develop.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes reach the query/variable construction in `developRunList` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L319) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:319](pkg/cmd/issue/develop/develop.go#L319) - `developRunList`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
