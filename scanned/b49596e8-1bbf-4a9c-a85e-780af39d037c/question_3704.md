# Q3704: HTTP method/route confusion from user input - startPage in pagination.go

## Question
Can a repo/remote/host string or API response field the attacker publishes reaching `startPage` in [pkg/cmd/api/pagination.go](pkg/cmd/api/pagination.go#L210) change the effective route (path traversal in the API path, extra query parameters) so a read command performs a write?

## Target
- File/function: [pkg/cmd/api/pagination.go:210](pkg/cmd/api/pagination.go#L210) - `startPage`
- Entrypoint: gh api pagination
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish an object whose name embeds `../` and reaches the path builder.
- Invariant to test: Path segments are escaped; methods are fixed per operation.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting the resulting method+path for hostile names.
