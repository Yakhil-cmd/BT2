# Q1279: non-http scheme opened - viewRun in view.go

## Question
Can the URL opened by `viewRun` in [pkg/cmd/issue/view/view.go](pkg/cmd/issue/view/view.go#L97) come from remote data (an issue/PR title, body, comment, check output, or release note the attacker authored) and carry a scheme other than http(s) - `javascript:`, `file:`, `vscode:`, `ms-msdt:`, `smb:` - which the OS handler executes?

## Target
- File/function: [pkg/cmd/issue/view/view.go:97](pkg/cmd/issue/view/view.go#L97) - `viewRun`
- Entrypoint: gh issue view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object whose URL field the victim opens with gh issue view.
- Invariant to test: Only http/https URLs on validated hosts are handed to the OS opener.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile schemes asserting the opener is never called.
