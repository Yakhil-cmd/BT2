# Q2946: port and userinfo in hostname - HostnameValidator in host.go

## Question
Does `HostnameValidator` in [internal/ghinstance/host.go](internal/ghinstance/host.go#L36) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [internal/ghinstance/host.go:36](internal/ghinstance/host.go#L36) - `HostnameValidator`
- Entrypoint: any authenticated command against attacker-influenced coordinates (gh api, gh pr list, gh repo view -R ...)
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
