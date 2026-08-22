# Q1353: terminal command injection via escape - newSSHCmd in ssh.go

## Question
Can attacker-supplied text rendered by `newSSHCmd` in [pkg/cmd/codespace/ssh.go](pkg/cmd/codespace/ssh.go#L49) carry sequences that terminals execute or auto-report (OSC 8 with a non-http URI, bracketed-paste break, title-set-then-report), turning display into command execution?

## Target
- File/function: [pkg/cmd/codespace/ssh.go:49](pkg/cmd/codespace/ssh.go#L49) - `newSSHCmd`
- Entrypoint: gh codespace ssh
- Attacker controls: codespace/API response fields and everything the codespace-side process sends back
- Exploit idea: Embed the payload in a PR title/body/check output the victim displays.
- Invariant to test: Only a safe subset of styling is emitted; hyperlinks are restricted to http(s).
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting rendered hyperlinks/URIs are scheme-checked and controls stripped.
