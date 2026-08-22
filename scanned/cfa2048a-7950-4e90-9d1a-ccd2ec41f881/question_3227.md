# Q3227: publish uploads unintended local files - buildTree in preview.go

## Question
Can `buildTree` in [pkg/cmd/skills/preview/preview.go](pkg/cmd/skills/preview/preview.go#L501) be induced by repository content (globs, symlinks, .gitignore handling) to package and upload files outside the skill directory, such as the victim's config or keys?

## Target
- File/function: [pkg/cmd/skills/preview/preview.go:501](pkg/cmd/skills/preview/preview.go#L501) - `buildTree`
- Entrypoint: gh skills preview
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Publish a template repo whose skill layout links to the user's home directory.
- Invariant to test: Packaging resolves links and refuses anything outside the skill root.
- Expected Immunefi impact: High - Arbitrary local file read / private data exfiltrated to an attacker-visible destination
- Fast validation: Test asserting the packaged file list for a hostile layout.
