# Q5888: manifest/pin file rewritten by the extension - hasScript in http.go

## Question
Can an installed extension's own files, processed by `hasScript` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L45), alter gh's recorded metadata (version pin, source repo, executable name) to persist or escalate?

## Target
- File/function: [pkg/cmd/extension/http.go:45](pkg/cmd/extension/http.go#L45) - `hasScript`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Ship a manifest that rewrites the recorded source on first run.
- Invariant to test: gh-owned metadata is never read back from extension-controlled files as authoritative.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting metadata integrity after installing hostile content.
