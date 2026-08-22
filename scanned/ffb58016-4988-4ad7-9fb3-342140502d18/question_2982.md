# Q2982: TLS verification weakened on a branch - fillPlaceholders in api.go

## Question
Is there a code path through `fillPlaceholders` in [pkg/cmd/api/api.go](pkg/cmd/api/api.go#L574) where a custom transport, test hook, or insecure flag disables certificate verification in a build users actually run?

## Target
- File/function: [pkg/cmd/api/api.go:574](pkg/cmd/api/api.go#L574) - `fillPlaceholders`
- Entrypoint: gh api
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Reach the branch via normal flags/env in a release build.
- Invariant to test: TLS verification is never disabled in non-test code.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the production transport has no InsecureSkipVerify.
