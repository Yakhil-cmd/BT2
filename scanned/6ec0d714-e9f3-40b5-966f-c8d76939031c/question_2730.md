# Q2730: non-http scheme opened - New in browser.go

## Question
Can the URL opened by `New` in [internal/browser/browser.go](internal/browser/browser.go#L13) come from remote data (an issue/PR title, body, comment, check output, or release note the attacker authored) and carry a scheme other than http(s) - `javascript:`, `file:`, `vscode:`, `ms-msdt:`, `smb:` - which the OS handler executes?

## Target
- File/function: [internal/browser/browser.go:13](internal/browser/browser.go#L13) - `New`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish an object whose URL field the victim opens with gh pr view.
- Invariant to test: Only http/https URLs on validated hosts are handed to the OS opener.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Table test of hostile schemes asserting the opener is never called.
