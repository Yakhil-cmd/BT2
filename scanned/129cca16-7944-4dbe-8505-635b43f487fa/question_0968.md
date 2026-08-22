# Q0968: install runs attacker code - hasScript in http.go

## Question
Can `hasScript` in [pkg/cmd/extension/http.go](pkg/cmd/extension/http.go#L45) execute code from the extension repository during install/upgrade (build scripts, hooks, Makefile, post-install step) before the user ever runs the extension?

## Target
- File/function: [pkg/cmd/extension/http.go:45](pkg/cmd/extension/http.go#L45) - `hasScript`
- Entrypoint: gh extension http
- Attacker controls: an extension repository, its release assets, and its manifest fields
- Exploit idea: Publish a `gh-` prefixed repo containing the payload and get the victim to install it.
- Invariant to test: Installation only copies/downloads files; nothing from the repo is executed at install time.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Integration test installing a fixture extension with hooks asserting no execution.
