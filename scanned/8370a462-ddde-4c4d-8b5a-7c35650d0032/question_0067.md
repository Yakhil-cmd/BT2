# Q0067: host from override flag/env unchecked - (HelperConfig).ConfigureOurs in helper_config.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `ConfigureOurs` in [pkg/cmd/auth/shared/gitcredentials/helper_config.go](pkg/cmd/auth/shared/gitcredentials/helper_config.go#L22) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [pkg/cmd/auth/shared/gitcredentials/helper_config.go:22](pkg/cmd/auth/shared/gitcredentials/helper_config.go#L22) - `(HelperConfig).ConfigureOurs`
- Entrypoint: gh auth
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
