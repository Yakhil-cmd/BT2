# Q4079: download URL host not validated - ListGists in shared.go

## Question
Can the download URL used by `ListGists` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L103) come from the API object (attacker-owned) and point at a host that then receives the victim's Authorization header?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:103](pkg/cmd/gist/shared/shared.go#L103) - `ListGists`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose download URL points at a collector.
- Invariant to test: Download targets are host-validated and unauthenticated when off-host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test asserting no credentials leave the authenticated host.
