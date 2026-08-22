# Q1726: preview renders untrusted skill content - acquireFLock in lockfile.go

## Question
Does `acquireFLock` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L155) print skill content (description, instructions, file list) to the terminal without sanitizing control sequences?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:155](internal/skills/lockfile/lockfile.go#L155) - `acquireFLock`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a skill whose description contains OSC/CSI payloads.
- Invariant to test: All skill-sourced text is sanitized before display.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Golden test over a hostile skill fixture.
