# Q2511: trusted root / TUF fallback - filterHiddenDirSkills in preview.go

## Question
Can `filterHiddenDirSkills` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L423) be pushed onto an embedded, cached, or attacker-served trusted root when the live TUF refresh fails or is stale?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:423](pkg/cmd/skills/preview/preview.go#L423) - `filterHiddenDirSkills`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Fail the TUF endpoint for the victim's request and observe which root is used.
- Invariant to test: Trust material is either freshly verified or the operation aborts.
- Expected Immunefi impact: Critical - Supply-chain verification bypass: unsigned or wrongly attributed artifact reported as verified
- Fast validation: Test with a failing TUF client asserting no fallback acceptance.
