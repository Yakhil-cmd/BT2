# Q3541: terminal command injection via escape - downloadCopilot in copilot.go

## Question
Can attacker-supplied text rendered by `downloadCopilot` in [pkg/cmd/copilot/copilot.go](pkg/cmd/copilot/copilot.go#L239) carry sequences that terminals execute or auto-report (OSC 8 with a non-http URI, bracketed-paste break, title-set-then-report), turning display into command execution?

## Target
- File/function: [pkg/cmd/copilot/copilot.go:239](pkg/cmd/copilot/copilot.go#L239) - `downloadCopilot`
- Entrypoint: gh copilot copilot
- Attacker controls: an imported alias file, agent session input, release-notes text, or repo coordinates the attacker publishes
- Exploit idea: Embed the payload in a PR title/body/check output the victim displays.
- Invariant to test: Only a safe subset of styling is emitted; hyperlinks are restricted to http(s).
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting rendered hyperlinks/URIs are scheme-checked and controls stripped.
