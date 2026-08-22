# Q1942: port and userinfo in hostname - updateGist in edit.go

## Question
Does `updateGist` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L399) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:399](pkg/cmd/gist/edit/edit.go#L399) - `updateGist`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
