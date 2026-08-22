# Q3136: case, trailing dot, and IDN normalization - mightBeGHESUser in cmd.go

## Question
Can `mightBeGHESUser` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L482) be fed `GitHub.com.`, an IDN homograph, or a percent-encoded host that normalizes differently for the trust check than for the connection?

## Target
- File/function: [internal/ghcmd/cmd.go:482](internal/ghcmd/cmd.go#L482) - `mightBeGHESUser`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Use a trailing-dot or unicode variant in a remote URL so validation and dialing disagree.
- Invariant to test: Hostnames are lowercased, punycode-normalized, and dot-trimmed once, before both use sites.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz host strings asserting normalize(validate(h)) == host used to dial.
