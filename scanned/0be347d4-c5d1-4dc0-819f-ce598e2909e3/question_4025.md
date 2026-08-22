# Q4025: cache key omits host or auth identity - runDownload in download.go

## Question
Does the caching in `runDownload` in [pkg/cmd/attestation/download/download.go](pkg/cmd/attestation/download/download.go#L126) key entries without the host/account, so a response fetched for an attacker host or unauthenticated context is served for a trusted one?

## Target
- File/function: [pkg/cmd/attestation/download/download.go:126](pkg/cmd/attestation/download/download.go#L126) - `runDownload`
- Entrypoint: gh attestation download
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Make the victim touch an attacker host first, then a trusted one, in the same or a later run.
- Invariant to test: Cache keys include scheme, host, account, and auth state.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test issuing two same-path requests on different hosts asserting no cross-serving.
