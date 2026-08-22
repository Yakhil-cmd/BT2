# Q0298: digest recorded but not verified - acquireFLock in lockfile.go

## Question
Does `acquireFLock` in [internal/skills/lockfile/lockfile.go](internal/skills/lockfile/lockfile.go#L155) store a content hash without comparing it to the downloaded bytes (or compare after writing them to their final location)?

## Target
- File/function: [internal/skills/lockfile/lockfile.go:155](internal/skills/lockfile/lockfile.go#L155) - `acquireFLock`
- Entrypoint: gh skills install
- Attacker controls: a published skill's archive entries, frontmatter, and registry metadata
- Exploit idea: Serve content that differs from the advertised digest.
- Invariant to test: Digests are verified on the downloaded bytes before anything is moved into place.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test with mismatched content asserting failure and no files left behind.
