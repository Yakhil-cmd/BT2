# Q5877: manifest/pin file rewritten by the extension - repoFromPath in manager.go

## Question
Can an installed extension's own files, processed by `repoFromPath` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L772), alter gh's recorded metadata (version pin, source repo, executable name) to persist or escalate?

## Target
- File/function: [pkg/cmd/extension/manager.go:772](pkg/cmd/extension/manager.go#L772) - `repoFromPath`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Ship a manifest that rewrites the recorded source on first run.
- Invariant to test: gh-owned metadata is never read back from extension-controlled files as authoritative.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting metadata integrity after installing hostile content.
