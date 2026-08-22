# Q4082: terminal command injection via escape - NewCmdEdit in edit.go

## Question
Can attacker-supplied text rendered by `NewCmdEdit` in [pkg/cmd/gist/edit/edit.go](pkg/cmd/gist/edit/edit.go#L45) carry sequences that terminals execute or auto-report (OSC 8 with a non-http URI, bracketed-paste break, title-set-then-report), turning display into command execution?

## Target
- File/function: [pkg/cmd/gist/edit/edit.go:45](pkg/cmd/gist/edit/edit.go#L45) - `NewCmdEdit`
- Entrypoint: gh gist edit
- Attacker controls: an asset, artifact, gist, or archive-member name and its bytes
- Exploit idea: Embed the payload in a PR title/body/check output the victim displays.
- Invariant to test: Only a safe subset of styling is emitted; hyperlinks are restricted to http(s).
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting rendered hyperlinks/URIs are scheme-checked and controls stripped.
