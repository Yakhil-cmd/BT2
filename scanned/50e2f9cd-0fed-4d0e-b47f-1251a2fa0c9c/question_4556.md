# Q4556: install runs attacker code - Main in cmd.go

## Question
Can `Main` in [internal/ghcmd/cmd.go](internal/ghcmd/cmd.go#L52) execute code from the extension repository during install/upgrade (build scripts, hooks, Makefile, post-install step) before the user ever runs the extension?

## Target
- File/function: [internal/ghcmd/cmd.go:52](internal/ghcmd/cmd.go#L52) - `Main`
- Entrypoint: gh extension install
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a `gh-` prefixed repo containing the payload and get the victim to install it.
- Invariant to test: Installation only copies/downloads files; nothing from the repo is executed at install time.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Integration test installing a fixture extension with hooks asserting no execution.
