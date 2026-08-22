# Q3603: case, trailing dot, and IDN normalization - getToken in multi_account.go

## Question
Can `getToken` in [internal/config/migration/multi_account.go](internal/config/migration/multi_account.go#L139) be fed `GitHub.com.`, an IDN homograph, or a percent-encoded host that normalizes differently for the trust check than for the connection?

## Target
- File/function: [internal/config/migration/multi_account.go:139](internal/config/migration/multi_account.go#L139) - `getToken`
- Entrypoint: gh auth login
- Attacker controls: a hostname, OAuth/device response, or git credential-protocol input the attacker supplies
- Exploit idea: Use a trailing-dot or unicode variant in a remote URL so validation and dialing disagree.
- Invariant to test: Hostnames are lowercased, punycode-normalized, and dot-trimmed once, before both use sites.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Fuzz host strings asserting normalize(validate(h)) == host used to dial.
