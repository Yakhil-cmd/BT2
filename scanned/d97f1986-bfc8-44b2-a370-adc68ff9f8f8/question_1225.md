# Q1225: CRLF/header injection via path or query - GetRawGistFile in shared.go

## Question
Can an asset, artifact, gist, or archive-member name and its bytes reach the request path/query built in `GetRawGistFile` in [pkg/cmd/gist/shared/shared.go](pkg/cmd/gist/shared/shared.go#L258) unescaped, allowing `?`, `#`, `/../`, or encoded CRLF to change the effective endpoint?

## Target
- File/function: [pkg/cmd/gist/shared/shared.go:258](pkg/cmd/gist/shared/shared.go#L258) - `GetRawGistFile`
- Entrypoint: gh gist
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Use a repo/branch/asset name containing `../` or `%0d%0a` so the request targets a different API route.
- Invariant to test: All path segments are URL-escaped individually before assembly.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting the final URL for hostile names equals the escaped expectation.
