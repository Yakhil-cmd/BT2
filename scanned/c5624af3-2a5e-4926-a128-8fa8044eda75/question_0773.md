# Q0773: case, trailing dot, and IDN normalization - setupGitRun in setupgit.go

## Question
Can `setupGitRun` in [pkg/cmd/auth/setupgit/setupgit.go](pkg/cmd/auth/setupgit/setupgit.go#L75) be fed `GitHub.com.`, an IDN homograph, or a percent-encoded host that normalizes differently for the trust check than for the connection?

## Target
- File/function: [pkg/cmd/auth/setupgit/setupgit.go:75](pkg/cmd/auth/setupgit/setupgit.go#L75) - `setupGitRun`
- Entrypoint: gh auth setupgit
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Use a trailing-dot or unicode variant in a remote URL so validation and dialing disagree.
- Invariant to test: Hostnames are lowercased, punycode-normalized, and dot-trimmed once, before both use sites.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz host strings asserting normalize(validate(h)) == host used to dial.
