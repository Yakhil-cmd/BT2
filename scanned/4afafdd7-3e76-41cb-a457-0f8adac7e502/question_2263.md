# Q2263: plaintext fallback for token storage - (remoteResolver).Resolver in remote_resolver.go

## Question
Does `Resolver` in [pkg/cmd/factory/remote_resolver.go](pkg/cmd/factory/remote_resolver.go#L28) silently fall back from the OS keyring to a plaintext config file when an attacker-triggerable error occurs?

## Target
- File/function: [pkg/cmd/factory/remote_resolver.go:28](pkg/cmd/factory/remote_resolver.go#L28) - `(remoteResolver).Resolver`
- Entrypoint: gh factory remote
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Cause the keyring path to fail during an attacker-initiated flow, leaving the token on disk.
- Invariant to test: Storage downgrade is explicit, user-visible, and file-permission protected.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test injecting a keyring error and asserting either failure or a 0600 file plus a warning.
