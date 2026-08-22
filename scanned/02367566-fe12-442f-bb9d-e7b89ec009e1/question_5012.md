# Q5012: device/web flow bound to the wrong host - (cfg).Migrate in config.go

## Question
Does `Migrate` in [internal/config/config.go](internal/config/config.go#L182) accept the OAuth endpoints (authorize/token/device URLs) from data the attacker can influence rather than deriving them from the validated host?

## Target
- File/function: [internal/config/config.go:182](internal/config/config.go#L182) - `(cfg).Migrate`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Serve endpoint metadata pointing token exchange at an attacker collector.
- Invariant to test: OAuth endpoints are derived from the validated host constant.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the token exchange URL host equals the login host.
