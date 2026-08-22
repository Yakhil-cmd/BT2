# Q0106: download URL host not validated - (Absolute).Join in absolute.go

## Question
Can the download URL used by `Join` in [internal/safepaths/absolute.go](internal/safepaths/absolute.go#L38) come from the API object (attacker-owned) and point at a host that then receives the victim's Authorization header?

## Target
- File/function: [internal/safepaths/absolute.go:38](internal/safepaths/absolute.go#L38) - `(Absolute).Join`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose download URL points at a collector.
- Invariant to test: Download targets are host-validated and unauthenticated when off-host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test asserting no credentials leave the authenticated host.
