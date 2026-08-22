# Q0369: width/emoji handling desync - filterHiddenDirSkills in preview.go

## Question
Can zero-width, RTL-override, or combining characters in a published skill's archive entries, frontmatter, and registry metadata rendered by `filterHiddenDirSkills` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L423) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:423](pkg/cmd/skills/preview/preview.go#L423) - `filterHiddenDirSkills`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
