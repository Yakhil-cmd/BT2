# Q5264: install runs attacker code - NewCmdRoot in root.go

## Question
Can `NewCmdRoot` in [pkg/cmd/root/root.go](pkg/cmd/root/root.go#L64) execute code from the extension repository during install/upgrade (build scripts, hooks, Makefile, post-install step) before the user ever runs the extension?

## Target
- File/function: [pkg/cmd/root/root.go:64](pkg/cmd/root/root.go#L64) - `NewCmdRoot`
- Entrypoint: gh root root
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a `gh-` prefixed repo containing the payload and get the victim to install it.
- Invariant to test: Installation only copies/downloads files; nothing from the repo is executed at install time.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Integration test installing a fixture extension with hooks asserting no execution.
