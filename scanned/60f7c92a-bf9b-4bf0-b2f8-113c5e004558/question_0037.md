# Q0037: host from override flag/env unchecked - keyringServiceName in multi_account.go

## Question
Can a `-R OWNER/REPO`-style override or env-provided host flowing into `keyringServiceName` in [internal/config/migration/multi_account.go](internal/config/migration/multi_account.go#L222) redirect authenticated traffic to an unauthenticated or attacker host?

## Target
- File/function: [internal/config/migration/multi_account.go:222](internal/config/migration/multi_account.go#L222) - `keyringServiceName`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Get the victim to run a documented command form on attacker-supplied repo coordinates.
- Invariant to test: Overrides are parsed strictly and resolved against configured hosts before any request.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test of override strings asserting rejection of embedded hosts/URLs.
