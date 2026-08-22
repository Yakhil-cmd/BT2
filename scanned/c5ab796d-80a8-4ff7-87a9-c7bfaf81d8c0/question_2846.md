# Q2846: ssh key material handled unsafely - putOrgSecret in http.go

## Question
Can `putOrgSecret` in [pkg/cmd/secret/set/http.go](pkg/cmd/secret/set/http.go#L85) write, read, or display private key material with weak permissions or into a path influenced by remote data?

## Target
- File/function: [pkg/cmd/secret/set/http.go:85](pkg/cmd/secret/set/http.go#L85) - `putOrgSecret`
- Entrypoint: gh secret set
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Trigger the flow with attacker-influenced naming.
- Invariant to test: Key files are 0600 in the user's own directory and never echoed.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Test asserting file mode and output redaction.
