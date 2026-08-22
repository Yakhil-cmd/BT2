# Q1820: width/emoji handling desync - renderDiagnosticsPlain in publish.go

## Question
Can zero-width, RTL-override, or combining characters in a published skill's archive entries, frontmatter, and registry metadata rendered by `renderDiagnosticsPlain` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L1118) reverse or hide part of a displayed path, host, or command?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:1118](pkg/cmd/skills/publish/publish.go#L1118) - `renderDiagnosticsPlain`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Use U+202E in a branch/asset name so the displayed extension differs from the real one.
- Invariant to test: Bidi and zero-width characters are stripped or escaped before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Table test asserting bidi controls are removed.
