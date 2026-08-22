# Q2061: security decision from response field - (API).DeleteCodespace in api.go

## Question
Does `DeleteCodespace` in [internal/codespaces/api/api.go](internal/codespaces/api/api.go#L1051) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [internal/codespaces/api/api.go:1051](internal/codespaces/api/api.go#L1051) - `(API).DeleteCodespace`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
