# Q0279: upgrade check pulls from attacker-chosen source - executable in cmd.go

## Question
Can the upgrade path in `executable` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L444) be pointed at a repository or host different from the one originally installed (renamed repo, redirect, changed remote)?

## Target
- File/function: [internal/ghcmd/cmd.go:444](internal/ghcmd/cmd.go#L444) - `executable`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Have the original extension repo redirect or transfer to an attacker account after install.
- Invariant to test: Upgrades are pinned to the originally installed host/owner/repo and re-verified.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting the upgrade fetch target equals the recorded source.
