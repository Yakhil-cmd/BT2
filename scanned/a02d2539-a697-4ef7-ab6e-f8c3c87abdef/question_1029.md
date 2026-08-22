# Q1029: skill name collision hijacks an installed skill - DiscoverSkillsWithOptions in discovery.go

## Question
Can a newly published skill processed by `DiscoverSkillsWithOptions` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L575) collide with an already-installed one (case, unicode, separator) and replace it?

## Target
- File/function: [internal/skills/discovery/discovery.go:575](internal/skills/discovery/discovery.go#L575) - `DiscoverSkillsWithOptions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish `My-Skill` to shadow `my-skill`.
- Invariant to test: Collisions are detected on normalized names and rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with colliding names asserting rejection.
