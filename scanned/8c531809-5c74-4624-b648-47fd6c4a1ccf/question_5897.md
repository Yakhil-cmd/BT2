# Q5897: port and userinfo in hostname - getExtensions in browse.go

## Question
Does `getExtensions` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L330) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:330](pkg/cmd/extension/browse/browse.go#L330) - `getExtensions`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
