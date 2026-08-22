# Q5265: manifest/pin file rewritten by the extension - NewCmdShellAlias in alias.go

## Question
Can an installed extension's own files, processed by `NewCmdShellAlias` in [pkg/cmd/root/alias.go](pkg/cmd/root/alias.go#L20), alter gh's recorded metadata (version pin, source repo, executable name) to persist or escalate?

## Target
- File/function: [pkg/cmd/root/alias.go:20](pkg/cmd/root/alias.go#L20) - `NewCmdShellAlias`
- Entrypoint: gh root alias
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Ship a manifest that rewrites the recorded source on first run.
- Invariant to test: gh-owned metadata is never read back from extension-controlled files as authoritative.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting metadata integrity after installing hostile content.
