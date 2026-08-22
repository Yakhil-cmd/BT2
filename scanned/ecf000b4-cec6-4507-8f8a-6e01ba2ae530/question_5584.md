# Q5584: newline/control chars in the URL - New in browser.go

## Question
Does `New` in [internal/browser/browser.go](internal/browser/browser.go#L13) accept a URL containing CR/LF or NUL from remote data before invoking the opener?

## Target
- File/function: [internal/browser/browser.go:13](internal/browser/browser.go#L13) - `New`
- Entrypoint: gh pr view
- Attacker controls: an issue/PR title, body, comment, check output, or release note the attacker authored
- Exploit idea: Publish a URL with `%0a` that splits into a second command on some platforms.
- Invariant to test: URLs with control characters are rejected.
- Expected Immunefi impact: Critical - Remote code execution on the victim's developer machine (GitHub Bug Bounty: RCE in gh; Immunefi 'Websites and Apps' class: arbitrary code execution)
- Fast validation: Fuzz test asserting rejection of control characters.
