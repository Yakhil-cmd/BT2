# Q4797: download URL host not validated - updateGist in edit.go

## Question
Can the download URL used by `updateGist` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L399) come from the API object (attacker-owned) and point at a host that then receives the victim's Authorization header?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:399](pkg/cmd/gist/edit/edit.go#L399) - `updateGist`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose download URL points at a collector.
- Invariant to test: Download targets are host-validated and unauthenticated when off-host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test asserting no credentials leave the authenticated host.
