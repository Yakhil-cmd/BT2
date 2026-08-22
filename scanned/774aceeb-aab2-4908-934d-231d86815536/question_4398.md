# Q4398: TLS verification weakened on a branch - plainHttpClientFunc in default.go

## Question
Is there a code path through `plainHttpClientFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L211) where a custom transport, test hook, or insecure flag disables certificate verification in a build users actually run?

## Target
- File/function: [pkg/cmd/factory/default.go:211](pkg/cmd/factory/default.go#L211) - `plainHttpClientFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Reach the branch via normal flags/env in a release build.
- Invariant to test: TLS verification is never disabled in non-test code.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting the production transport has no InsecureSkipVerify.
