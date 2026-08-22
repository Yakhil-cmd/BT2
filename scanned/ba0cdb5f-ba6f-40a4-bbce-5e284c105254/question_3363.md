# Q3363: port and userinfo in hostname - GetGist in shared.go

## Question
Does `GetGist` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L64) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:64](pkg/cmd/gist/shared/shared.go#L64) - `GetGist`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
