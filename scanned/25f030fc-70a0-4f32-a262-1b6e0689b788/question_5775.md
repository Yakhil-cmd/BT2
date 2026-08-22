# Q5775: host from override flag/env unchecked - (remoteResolver).Resolver in remote_resolver.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `Resolver` in [pkg/cmd/factory/remote_resolver.go](pkg/cmd/factory/remote_resolver.go#L28) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [pkg/cmd/factory/remote_resolver.go:28](pkg/cmd/factory/remote_resolver.go#L28) - `(remoteResolver).Resolver`
- Entrypoint: gh factory remote
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
