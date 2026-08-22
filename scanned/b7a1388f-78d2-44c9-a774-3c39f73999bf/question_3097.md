# Q3097: upgrade check pulls from attacker-chosen source - NewCmdExtension in command.go

## Question
Can the upgrade path in `NewCmdExtension` in [pkg/cmd/extension/command.go](pkg/cmd/extension/command.go#L28) be pointed at a repository or host different from the one originally installed (renamed repo, redirect, changed remote)?

## Target
- File/function: [pkg/cmd/extension/command.go:28](pkg/cmd/extension/command.go#L28) - `NewCmdExtension`
- Entrypoint: gh extension command
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Have the original extension repo redirect or transfer to an attacker account after install.
- Invariant to test: Upgrades are pinned to the originally installed host/owner/repo and re-verified.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the upgrade fetch target equals the recorded source.
