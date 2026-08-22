# Q1228: unauthenticated fallback on error - updateGist in edit.go

## Question
When authentication fails inside `updateGist` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L399), does it retry unauthenticated (or against a different host) and continue as if it had succeeded?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:399](pkg/cmd/gist/edit/edit.go#L399) - `updateGist`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Force a 401 from the attacker-controlled host and observe the fallback request.
- Invariant to test: Auth failure aborts; no silent downgrade.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test asserting a single failed request and an error.
