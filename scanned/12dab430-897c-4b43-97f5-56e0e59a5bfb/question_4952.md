# Q4952: CRLF/header injection via path or query - newCAPITransport in client.go

## Question
Can an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes reach the request path/query built in `newCAPITransport` in [pkg/cmd/agent-task/capi/client.go](pkg/cmd/agent-task/capi/client.go#L52) unescaped, allowing `?`, `#`, `/../`, or encoded CRLF to change the effective endpoint?

## Target
- File/function: [pkg/cmd/agent-task/capi/client.go:52](pkg/cmd/agent-task/capi/client.go#L52) - `newCAPITransport`
- Entrypoint: gh agent task
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Use a repo/branch/asset name containing `../` or `%0d%0a` so the request targets a different API route.
- Invariant to test: All path segments are URL-escaped individually before assembly.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting the final URL for hostile names equals the escaped expectation.
