# Q2412: upgrade check pulls from attacker-chosen source - NewCmdAlias in alias.go

## Question
Can the upgrade path in `NewCmdAlias` in [pkg/cmd/root/alias.go](pkg/cmd/root/alias.go#L54) be pointed at a repository or host different from the one originally installed (renamed repo, redirect, changed remote)?

## Target
- File/function: [pkg/cmd/root/alias.go:54](pkg/cmd/root/alias.go#L54) - `NewCmdAlias`
- Entrypoint: gh root alias
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Have the original extension repo redirect or transfer to an attacker account after install.
- Invariant to test: Upgrades are pinned to the originally installed host/owner/repo and re-verified.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the upgrade fetch target equals the recorded source.
