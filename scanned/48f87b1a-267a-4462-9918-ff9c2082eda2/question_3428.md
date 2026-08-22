# Q3428: terminal command injection via escape - PrintMessage in display.go

## Question
Can attacker-supplied text rendered by `PrintMessage` in [pkg/cmd/pr/shared/display.go](pkg/cmd/pr/shared/display.go#L62) carry sequences that terminals execute or auto-report (OSC 8 with a non-http URI, bracketed-paste break, title-set-then-report), turning display into command execution?

## Target
- File/function: [pkg/cmd/pr/shared/display.go:62](pkg/cmd/pr/shared/display.go#L62) - `PrintMessage`
- Entrypoint: gh pr
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Embed the payload in a PR title/body/check output the victim displays.
- Invariant to test: Only a safe subset of styling is emitted; hyperlinks are restricted to http(s).
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting rendered hyperlinks/URIs are scheme-checked and controls stripped.
