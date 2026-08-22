# Q5487: download URL host not validated - getZipLogMap in logs.go

## Question
Can the download URL used by `getZipLogMap` in [pkg/cmd/run/view/logs.go](pkg/cmd/run/view/logs.go#L221) come from the API object (attacker-owned) and point at a host that then receives the victim's Authorization header?

## Target
- File/function: [pkg/cmd/run/view/logs.go:221](pkg/cmd/run/view/logs.go#L221) - `getZipLogMap`
- Entrypoint: gh run view
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose download URL points at a collector.
- Invariant to test: Download targets are host-validated and unauthenticated when off-host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test asserting no credentials leave the authenticated host.
