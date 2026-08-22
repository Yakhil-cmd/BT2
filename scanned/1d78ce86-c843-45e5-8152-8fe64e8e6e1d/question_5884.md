# Q5884: upgrade check pulls from attacker-chosen source - (Extension).IsPinned in extension.go

## Question
Can the upgrade path in `IsPinned` in [pkg/cmd/extension/extension.go](pkg/cmd/extension/extension.go#L150) be pointed at a repository or host different from the one originally installed (renamed repo, redirect, changed remote)?

## Target
- File/function: [pkg/cmd/extension/extension.go:150](pkg/cmd/extension/extension.go#L150) - `(Extension).IsPinned`
- Entrypoint: gh extension extension
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Have the original extension repo redirect or transfer to an attacker account after install.
- Invariant to test: Upgrades are pinned to the originally installed host/owner/repo and re-verified.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the upgrade fetch target equals the recorded source.
