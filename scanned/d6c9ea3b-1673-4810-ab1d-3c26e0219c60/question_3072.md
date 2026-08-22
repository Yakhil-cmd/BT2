# Q3072: case, trailing dot, and IDN normalization - formatRemoteURL in clone.go

## Question
Can `formatRemoteURL` in [pkg/cmd/gist/clone/clone.go](pkg/cmd/gist/clone/clone.go#L96) be fed `GitHub.com.`, an IDN homograph, or a percent-encoded host that normalizes differently for the trust check than for the connection?

## Target
- File/function: [pkg/cmd/gist/clone/clone.go:96](pkg/cmd/gist/clone/clone.go#L96) - `formatRemoteURL`
- Entrypoint: gh gist clone
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Use a trailing-dot or unicode variant in a remote URL so validation and dialing disagree.
- Invariant to test: Hostnames are lowercased, punycode-normalized, and dot-trimmed once, before both use sites.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz host strings asserting normalize(validate(h)) == host used to dial.
