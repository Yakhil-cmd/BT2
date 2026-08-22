# Q3832: upgrade check pulls from attacker-chosen source - (extList).toggleSelected in browse.go

## Question
Can the upgrade path in `toggleSelected` in [pkg/cmd/extension/browse/browse.go](pkg/cmd/extension/browse/browse.go#L144) be pointed at a repository or host different from the one originally installed (renamed repo, redirect, changed remote)?

## Target
- File/function: [pkg/cmd/extension/browse/browse.go:144](pkg/cmd/extension/browse/browse.go#L144) - `(extList).toggleSelected`
- Entrypoint: gh extension browse
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Have the original extension repo redirect or transfer to an attacker account after install.
- Invariant to test: Upgrades are pinned to the originally installed host/owner/repo and re-verified.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the upgrade fetch target equals the recorded source.
