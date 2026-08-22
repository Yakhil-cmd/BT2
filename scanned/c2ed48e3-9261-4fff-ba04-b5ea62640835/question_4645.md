# Q4645: skill name collision hijacks an installed skill - NewCmdPreview in preview.go

## Question
Can a newly published skill processed by `NewCmdPreview` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L44) collide with an already-installed one (case, unicode, separator) and replace it?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:44](pkg/cmd/skills/preview/preview.go#L44) - `NewCmdPreview`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish `My-Skill` to shadow `my-skill`.
- Invariant to test: Collisions are detected on normalized names and rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with colliding names asserting rejection.
