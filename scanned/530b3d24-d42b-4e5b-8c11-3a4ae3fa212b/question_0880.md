# Q0880: CRLF/header injection via path or query - NewRemote in objects.go

## Question
Can a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes reach the request path/query built in `NewRemote` in [git/objects.go](git/objects.go#L42) unescaped, allowing `?`, `#`, `/../`, or encoded CRLF to change the effective endpoint?

## Target
- File/function: [git/objects.go:42](git/objects.go#L42) - `NewRemote`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Use a repo/branch/asset name containing `../` or `%0d%0a` so the request targets a different API route.
- Invariant to test: All path segments are URL-escaped individually before assembly.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting the final URL for hostile names equals the escaped expectation.
