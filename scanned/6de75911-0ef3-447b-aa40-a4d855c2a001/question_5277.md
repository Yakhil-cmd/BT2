# Q5277: manifest/pin file rewritten by the extension - (cmdWithStderr).Output in run.go

## Question
Can an installed extension's own files, processed by `Output` in [internal/run/run.go](internal/run/run.go#L33), alter gh's recorded metadata (version pin, source repo, executable name) to persist or escalate?

## Target
- File/function: [internal/run/run.go:33](internal/run/run.go#L33) - `(cmdWithStderr).Output`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Ship a manifest that rewrites the recorded source on first run.
- Invariant to test: gh-owned metadata is never read back from extension-controlled files as authoritative.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting metadata integrity after installing hostile content.
