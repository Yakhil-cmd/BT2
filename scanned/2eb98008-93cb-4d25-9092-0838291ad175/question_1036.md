# Q1036: digest recorded but not verified - FetchBlob in discovery.go

## Question
Does `FetchBlob` in [internal/skills/discovery/discovery.go](internal/skills/discovery/discovery.go#L918) store a content hash without comparing it to the downloaded bytes (or compare after writing them to their final location)?

## Target
- File/function: [internal/skills/discovery/discovery.go:918](internal/skills/discovery/discovery.go#L918) - `FetchBlob`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve content that differs from the advertised digest.
- Invariant to test: Digests are verified on the downloaded bytes before anything is moved into place.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with mismatched content asserting failure and no files left behind.
