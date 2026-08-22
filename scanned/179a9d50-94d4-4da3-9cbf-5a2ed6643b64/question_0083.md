# Q0083: GraphQL query assembled from remote strings - NewCachedHTTPClient in http_client.go

## Question
Can a repo/remote/host string or API response field the attacker publishes reach the query/variable construction in `NewCachedHTTPClient` in [api/http_client.go](api/http_client.go#L133) as raw query text rather than as a typed variable?

## Target
- File/function: [api/http_client.go:133](api/http_client.go#L133) - `NewCachedHTTPClient`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish an object whose name is interpolated into the query body.
- Invariant to test: All user/remote values are passed as GraphQL variables.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting the sent query body is constant and values travel in variables.
