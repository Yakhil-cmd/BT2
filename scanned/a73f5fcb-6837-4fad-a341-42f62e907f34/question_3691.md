# Q3691: host taken from repo remote - (remoteResolver).Resolver in remote_resolver.go

## Question
Does `Resolver` in [pkg/cmd/factory/remote_resolver.go](pkg/cmd/factory/remote_resolver.go#L28) accept the host embedded in a git remote URL of the repo the victim is standing in, without checking it against the authenticated hosts?

## Target
- File/function: [pkg/cmd/factory/remote_resolver.go:28](pkg/cmd/factory/remote_resolver.go#L28) - `(remoteResolver).Resolver`
- Entrypoint: gh factory remote
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish a repo whose `.git/config` remote (or submodule) points at an attacker host, then have the victim run gh factory remote inside a clone.
- Invariant to test: Hosts from repository metadata are only used after matching an authenticated host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test in a temp repo with a hostile remote asserting gh refuses or does not authenticate.
