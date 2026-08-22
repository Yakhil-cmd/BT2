# Q5165: port and userinfo in hostname - cloneRun in clone.go

## Question
Does `cloneRun` in [pkg/cmd/repo/clone/clone.go](pkg/cmd/repo/clone/clone.go#L111) keep or strip port/userinfo inconsistently, so the trust key differs from the connection target?

## Target
- File/function: [pkg/cmd/repo/clone/clone.go:111](pkg/cmd/repo/clone/clone.go#L111) - `cloneRun`
- Entrypoint: gh repo clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Supply `github.com:443@evil.tld` style values through a remote or flag.
- Invariant to test: Trust key and connection target derive from the same parsed URL fields.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz test asserting equality of trust key and dial host.
