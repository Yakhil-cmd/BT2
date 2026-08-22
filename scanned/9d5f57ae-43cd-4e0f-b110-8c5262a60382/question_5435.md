# Q5435: CRLF/header injection via path or query - normalizeReference in artifact.go

## Question
Can an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims reach the request path/query built in `normalizeReference` in [pkg/cmd/attestation/artifact/artifact.go](pkg/cmd/attestation/artifact/artifact.go#L30) unescaped, allowing `?`, `#`, `/../`, or encoded CRLF to change the effective endpoint?

## Target
- File/function: [pkg/cmd/attestation/artifact/artifact.go:30](pkg/cmd/attestation/artifact/artifact.go#L30) - `normalizeReference`
- Entrypoint: gh attestation
- Attacker controls: an artifact, its Sigstore bundle, and the attacker's own repo/workflow claims
- Exploit idea: Use a repo/branch/asset name containing `../` or `%0d%0a` so the request targets a different API route.
- Invariant to test: All path segments are URL-escaped individually before assembly.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting the final URL for hostile names equals the escaped expectation.
