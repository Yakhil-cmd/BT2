# Q0209: CRLF/header injection via path or query - linkedBranchRepoFromURL in develop.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes reach the request path/query built in `linkedBranchRepoFromURL` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L306) unescaped, allowing `?`, `#`, `/../`, or encoded CRLF to change the effective endpoint?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:306](pkg/cmd/issue/develop/develop.go#L306) - `linkedBranchRepoFromURL`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Use a repo/branch/asset name containing `../` or `%0d%0a` so the request targets a different API route.
- Invariant to test: All path segments are URL-escaped individually before assembly.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting the final URL for hostile names equals the escaped expectation.
