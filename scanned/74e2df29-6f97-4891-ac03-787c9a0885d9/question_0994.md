# Q0994: port and userinfo in hostname - mightBeGHESUser in cmd.go

## Question
Does `mightBeGHESUser` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L482) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [internal/ghcmd/cmd.go:482](internal/ghcmd/cmd.go#L482) - `mightBeGHESUser`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
