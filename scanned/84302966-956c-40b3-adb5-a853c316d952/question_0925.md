# Q0925: terminal command injection via escape - printLinkedBranches in develop.go

## Question
Can attacker-supplied text rendered by `printLinkedBranches` in [pkg/cmd/issue/develop/develop.go](pkg/cmd/issue/develop/develop.go#L342) carry sequences that terminals execute or auto-report (OSC 8 with a non-http URI, bracketed-paste break, title-set-then-report), turning display into command execution?

## Target
- File/function: [pkg/cmd/issue/develop/develop.go:342](pkg/cmd/issue/develop/develop.go#L342) - `printLinkedBranches`
- Entrypoint: gh issue develop
- Attacker controls: a repository, branch, tag, PR head ref, remote, or .gitmodules entry the attacker publishes
- Exploit idea: Embed the payload in a PR title/body/check output the victim displays.
- Invariant to test: Only a safe subset of styling is emitted; hyperlinks are restricted to http(s).
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Test asserting rendered hyperlinks/URIs are scheme-checked and controls stripped.
