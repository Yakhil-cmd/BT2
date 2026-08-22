# Q4399: security decision from response field - externalHttpClientFunc in default.go

## Question
Does `externalHttpClientFunc` in [pkg/cmd/factory/default.go](pkg/cmd/factory/default.go#L230) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [pkg/cmd/factory/default.go:230](pkg/cmd/factory/default.go#L230) - `externalHttpClientFunc`
- Entrypoint: gh factory default
- Attacker controls: a repo/remote/host string or API response field the attacker publishes
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
