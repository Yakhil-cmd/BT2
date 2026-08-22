# Q4571: host from override flag/env unchecked - ValidateSupportedHost in source.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `ValidateSupportedHost` in [internal/skills/source/source.go](internal/skills/source/source.go#L56) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [internal/skills/source/source.go:56](internal/skills/source/source.go#L56) - `ValidateSupportedHost`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
