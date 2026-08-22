# Q3202: prompt/output spoofing with CR and newline - printFileTree in install.go

## Question
Can carriage returns or newlines in a published skill's archive entries, frontmatter, and registry metadata rendered by `printFileTree` in [pkg/cmd/skills/install/install.go](pkg/cmd/skills/install/install.go#L1151) overwrite earlier lines and forge gh's own trusted output or a credential prompt?

## Target
- File/function: [pkg/cmd/skills/install/install.go:1151](pkg/cmd/skills/install/install.go#L1151) - `printFileTree`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Craft a name/title that redraws the line as `? Paste your GitHub token:`.
- Invariant to test: Remote text is escaped so it cannot emit CR or reposition the cursor.
- Expected Immunefi impact: High - Terminal output/prompt spoofing leading to credential capture or unintended destructive confirmation
- Fast validation: Test asserting `\r` and cursor-movement sequences never appear in rendered output.
