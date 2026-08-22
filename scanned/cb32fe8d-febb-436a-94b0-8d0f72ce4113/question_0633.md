# Q0633: CRLF/header injection via path or query - (API).DeleteCodespace in api.go

## Question
Can codespace/API response fields and everything the codespace-side process sends back reach the request path/query built in `DeleteCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1051) unescaped, allowing `?`, `#`, `/../`, or encoded CRLF to change the effective endpoint?

## Target
- File/function: [internal/codespaces/api/api.go:1051](internal/codespaces/api/api.go#L1051) - `(API).DeleteCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Use a repo/branch/asset name containing `../` or `%0d%0a` so the request targets a different API route.
- Invariant to test: All path segments are URL-escaped individually before assembly.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Table test asserting the final URL for hostile names equals the escaped expectation.
