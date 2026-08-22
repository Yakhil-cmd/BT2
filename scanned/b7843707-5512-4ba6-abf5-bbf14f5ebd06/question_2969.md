# Q2969: SSRF to internal addresses - HttpClientFunc in default.go

## Question
Can a URL derived from attacker-published data reaching `HttpClientFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L188) point at localhost, link-local (169.254.169.254), or an internal host, causing the victim's gh (often in CI) to fetch and surface internal data?

## Target
- File/function: [pkg/cmd/factory/default.go:188](pkg/cmd/factory/default.go#L188) - `HttpClientFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish an asset/codespace/skill URL pointing at the CI metadata service.
- Invariant to test: Only public, allowlisted hosts are fetched; literal IP and localhost targets are rejected.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Table test over internal targets asserting rejection.
