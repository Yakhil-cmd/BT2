# Q2268: HTTP method/route confusion from user input - fillPlaceholders in api.go

## Question
Can a repo/remote/host string or API response field the attacker publishes reaching `fillPlaceholders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L574) change the effective route (path traversal in the API path, extra query parameters) so a read command performs a write?

## Target
- File/function: [pkg/cmd/api/api.go:574](pkg/cmd/api/api.go#L574) - `fillPlaceholders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish an object whose name embeds `../` and reaches the path builder.
- Invariant to test: Path segments are escaped; methods are fixed per operation.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting the resulting method+path for hostile names.
