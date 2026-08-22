# Q4572: case, trailing dot, and IDN normalization - normalizeHost in source.go

## Question
Can `normalizeHost` in [internal/skills/source/source.go](internal/skills/source/source.go#L70) be fed `GitHub.com.`, an IDN homograph, or a percent-encoded host that normalizes differently for the trust check than for the connection?

## Target
- File/function: [internal/skills/source/source.go:70](internal/skills/source/source.go#L70) - `normalizeHost`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Use a trailing-dot or unicode variant in a remote URL so validation and dialing disagree.
- Invariant to test: Hostnames are lowercased, punycode-normalized, and dot-trimmed once, before both use sites.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz host strings asserting normalize(validate(h)) == host used to dial.
