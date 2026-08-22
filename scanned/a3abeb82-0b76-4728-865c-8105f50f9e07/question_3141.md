# Q3141: publish uploads unintended local files - InstallLocal in installer.go

## Question
Can `InstallLocal` in [internal/skills/installer/installer.go](internal/skills/installer/installer.go#L156) be induced by repository content (globs, symlinks, .gitignore handling) to package and upload files outside the skill directory, such as the victim's config or keys?

## Target
- File/function: [internal/skills/installer/installer.go:156](internal/skills/installer/installer.go#L156) - `InstallLocal`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a template repo whose skill layout links to the user's home directory.
- Invariant to test: Packaging resolves links and refuses anything outside the skill root.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the packaged file list for a hostile layout.
