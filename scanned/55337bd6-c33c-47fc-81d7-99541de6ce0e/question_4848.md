# Q4848: GraphQL query assembled from remote strings - viewRun in view.go

## Question
Can an issue/PR title, body, comment, check output, or release note the attacker authored reach the query/variable construction in `viewRun` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L97) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/issue/view/view.go:97](pkg/cmd/issue/view/view.go#L97) - `viewRun`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
