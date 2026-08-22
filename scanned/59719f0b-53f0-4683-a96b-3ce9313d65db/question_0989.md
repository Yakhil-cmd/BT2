# Q0989: manifest/pin file rewritten by the extension - authRecoveryCommand in cmd.go

## Question
Can an installed extension's own files, processed by `authRecoveryCommand` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L304), alter gh's recorded metadata (version pin, source repo, executable name) to persist or escalate?

## Target
- File/function: [internal/ghcmd/cmd.go:304](internal/ghcmd/cmd.go#L304) - `authRecoveryCommand`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Ship a manifest that rewrites the recorded source on first run.
- Invariant to test: gh-owned metadata is never read back from extension-controlled files as authoritative.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting metadata integrity after installing hostile content.
