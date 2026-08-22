# Q1777: discovery walks into attacker-controlled paths - printReviewHint in install.go

## Question
Can `printReviewHint` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1198) be made to traverse or follow links out of the skills root into other user directories while enumerating skills?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1198](pkg/cmd/skills/install/install.go#L1198) - `printReviewHint`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill containing a symlinked directory.
- Invariant to test: Enumeration does not follow links out of the root and bounds depth.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test with a symlinked fixture asserting confinement.
