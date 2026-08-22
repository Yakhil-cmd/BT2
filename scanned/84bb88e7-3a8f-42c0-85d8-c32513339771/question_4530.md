# Q4530: stale/pinned version downgrade - (Extension).Owner in extension.go

## Question
Can an attacker who controls the extension repository make `Owner` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L182) install an older, known-vulnerable version or skip the pin recorded locally?

## Target
- File/function: [pkg/cmd/extension/extension.go:182](pkg/cmd/extension/extension.go#L182) - `(Extension).Owner`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Re-tag the release so the resolved version differs from the pin.
- Invariant to test: Version resolution is pinned and monotonic, verified after download.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the installed version matches the pin.
