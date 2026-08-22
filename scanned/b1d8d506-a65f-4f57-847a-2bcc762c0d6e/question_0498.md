# Q0498: download URL host not validated - extractZipFile in zip.go

## Question
Can the download URL used by `extractZipFile` in [internal/zip/zip.go](internal/zip/zip.go#L42) come from the API object (attacker-owned) and point at a host that then receives the victim's Authorization header?

## Target
- File/function: [internal/zip/zip.go:42](internal/zip/zip.go#L42) - `extractZipFile`
- Entrypoint: gh run download
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Publish an object whose download URL points at a collector.
- Invariant to test: Download targets are host-validated and unauthenticated when off-host.
- Expected Immunefi impact: Critical - Exfiltration of the victim's GitHub OAuth token / git credentials to an attacker-controlled host (sensitive credential disclosure)
- Fast validation: httpmock test asserting no credentials leave the authenticated host.
