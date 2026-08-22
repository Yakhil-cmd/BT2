# Q1040: skill name collision hijacks an installed skill - FindNameCollisions in collisions.go

## Question
Can a newly published skill processed by `FindNameCollisions` in [internal/skills/discovery/collisions.go](internal/skills/discovery/collisions.go#L21) collide with an already-installed one (case, unicode, separator) and replace it?

## Target
- File/function: [internal/skills/discovery/collisions.go:21](internal/skills/discovery/collisions.go#L21) - `FindNameCollisions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish `My-Skill` to shadow `my-skill`.
- Invariant to test: Collisions are detected on normalized names and rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with colliding names asserting rejection.
