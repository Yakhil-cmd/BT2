# Q1230: download URL host not validated - NewCmdView in view.go

## Question
Can the download URL used by `NewCmdView` in [pkg/cmd/gist/view/view.go](pkg/cmd/gist/view/view.go#L42) come from the API object (attacker-owned) and point at a host that then receives the victim's Authorization header?

## Target
- File/function: [pkg/cmd/gist/view/view.go:42](pkg/cmd/gist/view/view.go#L42) - `NewCmdView`
- Entrypoint: gh gist view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose download URL points at a collector.
- Invariant to test: Download targets are host-validated and unauthenticated when off-host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test asserting no credentials leave the authenticated host.
