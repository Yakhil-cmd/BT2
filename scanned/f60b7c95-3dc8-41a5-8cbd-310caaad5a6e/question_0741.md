# Q0741: host from override flag/env unchecked - (AuthConfig).activateUser in config.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `activateUser` in [internal/config/config.go](internal/config/config.go#L460) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [internal/config/config.go:460](internal/config/config.go#L460) - `(AuthConfig).activateUser`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
