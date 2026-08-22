# Q2739: case, trailing dot, and IDN normalization - ListenTCP in codespaces.go

## Question
Can `ListenTCP` in [internal/codespaces/codespaces.go](internal/codespaces/codespaces.go#L132) be fed `GitHub.com.`, an IDN homograph, or a percent-encoded host that normalizes differently for the trust check than for the connection?

## Target
- File/function: [internal/codespaces/codespaces.go:132](internal/codespaces/codespaces.go#L132) - `ListenTCP`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Use a trailing-dot or unicode variant in a remote URL so validation and dialing disagree.
- Invariant to test: Hostnames are lowercased, punycode-normalized, and dot-trimmed once, before both use sites.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz host strings asserting normalize(validate(h)) == host used to dial.
