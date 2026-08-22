# Q3831: stale/pinned version downgrade - newExtList in browse.go

## Question
Can an attacker who controls the extension repository make `newExtList` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L110) install an older, known-vulnerable version or skip the pin recorded locally?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:110](pkg/cmd/extension/browse/browse.go#L110) - `newExtList`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Re-tag the release so the resolved version differs from the pin.
- Invariant to test: Version resolution is pinned and monotonic, verified after download.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the installed version matches the pin.
