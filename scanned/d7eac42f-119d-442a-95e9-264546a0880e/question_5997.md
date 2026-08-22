# Q5997: skill name collision hijacks an installed skill - checkImmutableReleases in publish.go

## Question
Can a newly published skill processed by `checkImmutableReleases` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L736) collide with an already-installed one (case, unicode, separator) and replace it?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:736](pkg/cmd/skills/publish/publish.go#L736) - `checkImmutableReleases`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish `My-Skill` to shadow `my-skill`.
- Invariant to test: Collisions are detected on normalized names and rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with colliding names asserting rejection.
