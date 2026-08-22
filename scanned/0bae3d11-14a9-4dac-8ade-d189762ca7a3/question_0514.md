# Q0514: host from override flag/env unchecked - updateGist in edit.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `updateGist` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L399) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:399](pkg/cmd/gist/edit/edit.go#L399) - `updateGist`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
