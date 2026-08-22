# Q3835: host from override flag/env unchecked - getExtensions in browse.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `getExtensions` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L330) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:330](pkg/cmd/extension/browse/browse.go#L330) - `getExtensions`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
