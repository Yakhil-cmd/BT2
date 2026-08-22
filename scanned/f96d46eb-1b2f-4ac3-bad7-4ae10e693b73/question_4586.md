# Q4586: security decision from response field - FetchRepoVisibility in discovery.go

## Question
Does `FetchRepoVisibility` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L191) branch on a boolean/permission/visibility field of the response that the attacker owns (their repo, their codespace, their gist) to decide what to write, execute, or trust locally?

## Target
- File/function: [internal/skills/discovery/discovery.go:191](internal/skills/discovery/discovery.go#L191) - `FetchRepoVisibility`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish an object with the field flipped and observe the local behaviour change.
- Invariant to test: Local trust decisions never depend on attacker-owned object fields.
- Expected Immunefi impact: Critical - Authentication/authorization bypass in gh: wrong account or host credentials used for a privileged action
- Fast validation: Test flipping the field asserting no change to the local security-relevant action.
