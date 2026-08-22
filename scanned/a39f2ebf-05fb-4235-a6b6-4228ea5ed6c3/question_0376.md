# Q0376: security decision from response field - fetchTags in publish.go

## Question
Does `fetchTags` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L464) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:464](pkg/cmd/skills/publish/publish.go#L464) - `fetchTags`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
