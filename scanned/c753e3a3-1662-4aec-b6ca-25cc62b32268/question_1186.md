# Q1186: CRLF/header injection via path or query - fetchReleasePath in fetch.go

## Question
Can an asset, artifact, gist, or archive-member name and its bytes reach the request path/query built in `fetchReleasePath` in [pkg/cmd/release/shared/fetch.go](pkg/cmd/release/shared/fetch.go#L281) unescaped, allowing `?`, `#`, `/../`, or encoded CRLF to change the effective endpoint?

## Target
- File/function: [pkg/cmd/release/shared/fetch.go:281](pkg/cmd/release/shared/fetch.go#L281) - `fetchReleasePath`
- Entrypoint: gh release
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Use a repo/branch/asset name containing `../` or `%0d%0a` so the request targets a different API route.
- Invariant to test: All path segments are URL-escaped individually before assembly.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting the final URL for hostile names equals the escaped expectation.
