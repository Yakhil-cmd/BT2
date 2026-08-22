# Q2379: upgrade check pulls from attacker-chosen source - repoFromPath in manager.go

## Question
Can the upgrade path in `repoFromPath` in [pkg/cmd/extension/manager.go](pkg/cmd/extension/manager.go#L772) be pointed at a repository or host different from the one originally installed (renamed repo, redirect, changed remote)?

## Target
- File/function: [pkg/cmd/extension/manager.go:772](pkg/cmd/extension/manager.go#L772) - `repoFromPath`
- Entrypoint: gh extension manager
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Have the original extension repo redirect or transfer to an attacker account after install.
- Invariant to test: Upgrades are pinned to the originally installed host/owner/repo and re-verified.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the upgrade fetch target equals the recorded source.
