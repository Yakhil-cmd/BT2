# Q1935: host from override flag/env unchecked - GetGist in shared.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `GetGist` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L64) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:64](pkg/cmd/gist/shared/shared.go#L64) - `GetGist`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
