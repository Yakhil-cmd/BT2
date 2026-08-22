# Q3769: GraphQL query assembled from remote strings - findForRefs in finder.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes reach the query/variable construction in `findForRefs` in [pkg/cmd/pr/shared/finder.go](pkg/cmd/pr/shared/finder.go#L386) as raw query text rather than as a typed variable?

## Target
- File/function: [pkg/cmd/pr/shared/finder.go:386](pkg/cmd/pr/shared/finder.go#L386) - `findForRefs`
- Entrypoint: gh pr
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
