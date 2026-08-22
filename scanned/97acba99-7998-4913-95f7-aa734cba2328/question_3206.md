# Q3206: skill name collision hijacks an installed skill - printHostHints in install.go

## Question
Can a newly published skill processed by `printHostHints` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1228) collide with an already-installed one (case, unicode, separator) and replace it?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1228](pkg/cmd/skills/install/install.go#L1228) - `printHostHints`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish `My-Skill` to shadow `my-skill`.
- Invariant to test: Collisions are detected on normalized names and rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with colliding names asserting rejection.
