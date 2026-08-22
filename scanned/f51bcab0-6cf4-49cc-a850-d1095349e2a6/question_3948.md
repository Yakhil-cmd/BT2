# Q3948: digest recorded but not verified - ensurePushed in publish.go

## Question
Does `ensurePushed` in [pkg/cmd/skills/publish/publish.go](pkg/cmd/skills/publish/publish.go#L640) store a content hash without comparing it to the downloaded bytes (or compare after writing them to their final location)?

## Target
- File/function: [pkg/cmd/skills/publish/publish.go:640](pkg/cmd/skills/publish/publish.go#L640) - `ensurePushed`
- Entrypoint: gh skills publish
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve content that differs from the advertised digest.
- Invariant to test: Digests are verified on the downloaded bytes before anything is moved into place.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with mismatched content asserting failure and no files left behind.
