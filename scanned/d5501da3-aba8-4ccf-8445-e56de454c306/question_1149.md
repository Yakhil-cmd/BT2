# Q1149: URL parsed twice with different results - (LiveClient).getBundle in client.go

## Question
Does `getBundle` in [pkg/cmd/attestation/api/client.go](pkg/cmd/attestation/api/client.go#L237) parse the same attacker string with two different parsers (url.Parse vs manual split vs git URL parser) so validation and use disagree?

## Target
- File/function: [pkg/cmd/attestation/api/client.go:237](pkg/cmd/attestation/api/client.go#L237) - `(LiveClient).getBundle`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Craft a URL that the two parsers read differently (`https://a@b/`, `ssh://`, `git@host:path`).
- Invariant to test: One parse result is computed once and reused for both the check and the action.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: Differential fuzz test comparing both parsers on random URLs.
