# Q4802: host from override flag/env unchecked - createRun in create.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `createRun` in [pkg/cmd/gist/create/create.go](pkg/cmd/gist/create/create.go#L108) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [pkg/cmd/gist/create/create.go:108](pkg/cmd/gist/create/create.go#L108) - `createRun`
- Entrypoint: gh gist create
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
