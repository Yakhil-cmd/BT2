# Q2510: discovery walks into attacker-controlled paths - renderMarkdownPreview in preview.go

## Question
Can `renderMarkdownPreview` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L392) be made to traverse or follow links out of the skills root into other user directories while enumerating skills?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:392](pkg/cmd/skills/preview/preview.go#L392) - `renderMarkdownPreview`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill containing a symlinked directory.
- Invariant to test: Enumeration does not follow links out of the root and bounds depth.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test with a symlinked fixture asserting confinement.
