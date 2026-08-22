# Q2376: port and userinfo in hostname - (Manager).goBinScaffolding in manager.go

## Question
Does `goBinScaffolding` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L670) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [pkg/cmd/extension/manager.go:670](pkg/cmd/extension/manager.go#L670) - `(Manager).goBinScaffolding`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
