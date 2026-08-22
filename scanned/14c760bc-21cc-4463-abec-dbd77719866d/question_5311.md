# Q5311: publish uploads unintended local files - DiscoverSkillsWithOptions in discovery.go

## Question
Can `DiscoverSkillsWithOptions` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L575) be induced by repository content (globs, symlinks, .gitignore handling) to package and upload files outside the skill directory, such as the victim's config or keys?

## Target
- File/function: [internal/skills/discovery/discovery.go:575](internal/skills/discovery/discovery.go#L575) - `DiscoverSkillsWithOptions`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a template repo whose skill layout links to the user's home directory.
- Invariant to test: Packaging resolves links and refuses anything outside the skill root.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the packaged file list for a hostile layout.
