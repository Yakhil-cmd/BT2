# Q3880: security decision from response field - resolveDefaultBranch in discovery.go

## Question
Does `resolveDefaultBranch` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L366) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [internal/skills/discovery/discovery.go:366](internal/skills/discovery/discovery.go#L366) - `resolveDefaultBranch`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
