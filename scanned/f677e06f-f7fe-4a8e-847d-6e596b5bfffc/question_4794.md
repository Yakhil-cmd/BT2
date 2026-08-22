# Q4794: unauthenticated fallback on error - GetRawGistFile in shared.go

## Question
When authentication fails inside `GetRawGistFile` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L258), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:258](pkg/cmd/gist/shared/shared.go#L258) - `GetRawGistFile`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
